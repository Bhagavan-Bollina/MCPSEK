package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/mcpsek/mcpsek/internal/database"
	"github.com/mcpsek/mcpsek/internal/discovery"
	"github.com/mcpsek/mcpsek/internal/scanner"
)

// Scheduler manages discovery and scanning
type Scheduler struct {
	db                *database.DB
	scanner           *scanner.Scanner
	npmDiscoverer     *discovery.NPMDiscoverer
	githubDiscoverer  *discovery.GitHubDiscoverer
	registryDiscoverer *discovery.RegistryDiscoverer
	workerCount       int
	scanInterval      time.Duration
	discoveryInterval time.Duration
}

// New creates a new scheduler
func New(db *database.DB, scn *scanner.Scanner, githubToken string, workerCount int, scanInterval, discoveryInterval time.Duration) *Scheduler {
	return &Scheduler{
		db:                 db,
		scanner:            scn,
		npmDiscoverer:      discovery.NewNPMDiscoverer(),
		githubDiscoverer:   discovery.NewGitHubDiscoverer(githubToken),
		registryDiscoverer: discovery.NewRegistryDiscoverer(),
		workerCount:        workerCount,
		scanInterval:       scanInterval,
		discoveryInterval:  discoveryInterval,
	}
}

// Start begins the scheduler loops
func (s *Scheduler) Start(ctx context.Context) error {
	log.Println("Scheduler starting")

	// Run initial discovery
	if err := s.runDiscovery(ctx); err != nil {
		log.Printf("Initial discovery failed: %v", err)
	}

	// Start discovery loop
	go s.discoveryLoop(ctx)

	// Start scan loop
	go s.scanLoop(ctx)

	<-ctx.Done()
	log.Println("Scheduler stopping")
	return nil
}

// discoveryLoop periodically discovers new servers
func (s *Scheduler) discoveryLoop(ctx context.Context) {
	ticker := time.NewTicker(s.discoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.runDiscovery(ctx); err != nil {
				log.Printf("Discovery error: %v", err)
			}
		}
	}
}

// runDiscovery executes discovery from all sources
func (s *Scheduler) runDiscovery(ctx context.Context) error {
	log.Println("Running discovery...")

	totalDiscovered := 0

	// Discover from npm
	npmServers, err := s.npmDiscoverer.Discover(ctx)
	if err != nil {
		log.Printf("NPM discovery error: %v", err)
	} else {
		if err := s.upsertServers(ctx, npmServers); err != nil {
			log.Printf("Error upserting npm servers: %v", err)
		} else {
			totalDiscovered += len(npmServers)
		}
	}

	// Discover from GitHub
	githubServers, err := s.githubDiscoverer.Discover(ctx)
	if err != nil {
		log.Printf("GitHub discovery error: %v", err)
	} else {
		if err := s.upsertServers(ctx, githubServers); err != nil {
			log.Printf("Error upserting GitHub servers: %v", err)
		} else {
			totalDiscovered += len(githubServers)
		}
	}

	// Discover from official registry
	registryServers, err := s.registryDiscoverer.Discover(ctx)
	if err != nil {
		log.Printf("Registry discovery error: %v", err)
	} else {
		if err := s.upsertServers(ctx, registryServers); err != nil {
			log.Printf("Error upserting registry servers: %v", err)
		} else {
			totalDiscovered += len(registryServers)
		}
	}

	log.Printf("Discovery complete: %d servers found", totalDiscovered)
	return nil
}

// upsertServers inserts or updates discovered servers in the database
func (s *Scheduler) upsertServers(ctx context.Context, discovered []*discovery.DiscoveredServer) error {
	for _, ds := range discovered {
		server := &database.Server{
			Name:            ds.Name,
			SourceURL:       ds.SourceURL,
			PackageRegistry: ds.PackageRegistry,
			PackageName:     ds.PackageName,
			Description:     ds.Description,
			Author:          ds.Author,
			License:         ds.License,
			Stars:           ds.Stars,
		}

		if err := s.db.UpsertServer(ctx, server); err != nil {
			log.Printf("Error upserting server %s: %v", ds.Name, err)
			continue
		}
	}
	return nil
}

// scanLoop periodically scans servers
func (s *Scheduler) scanLoop(ctx context.Context) {
	ticker := time.NewTicker(s.scanInterval)
	defer ticker.Stop()

	// Run initial scan
	s.runScanBatch(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runScanBatch(ctx)
		}
	}
}

// runScanBatch fetches and scans a batch of servers
func (s *Scheduler) runScanBatch(ctx context.Context) {
	// Get servers that need scanning
	servers, err := s.db.GetServersToScan(ctx, 100)
	if err != nil {
		log.Printf("Error getting servers to scan: %v", err)
		return
	}

	if len(servers) == 0 {
		log.Println("No servers need scanning")
		return
	}

	log.Printf("Scanning %d servers with %d workers", len(servers), s.workerCount)

	// Create job queue
	jobs := make(chan *database.Server, len(servers))
	for _, server := range servers {
		jobs <- server
	}
	close(jobs)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.workerCount; i++ {
		wg.Add(1)
		go s.scanWorker(ctx, &wg, jobs)
	}

	wg.Wait()
	log.Println("Scan batch complete")
}

// scanWorker processes scan jobs
func (s *Scheduler) scanWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan *database.Server) {
	defer wg.Done()

	for server := range jobs {
		if err := s.scanServer(ctx, server); err != nil {
			log.Printf("Scan failed for %s: %v", server.Name, err)
		} else {
			log.Printf("Scan complete for %s (score: %d)", server.Name, server.TrustScore)
		}
	}
}

// scanServer scans a single server
func (s *Scheduler) scanServer(ctx context.Context, server *database.Server) error {
	// Mark as scanning
	if err := s.db.UpdateServerScanStatus(ctx, server.ID, "scanning", nil); err != nil {
		return err
	}

	// Perform scan
	_, err := s.scanner.Scan(ctx, server.ID, server.SourceURL)
	if err != nil {
		errMsg := err.Error()
		s.db.UpdateServerScanStatus(ctx, server.ID, "failed", &errMsg)
		return err
	}

	// Status updated by scanner
	return nil
}
