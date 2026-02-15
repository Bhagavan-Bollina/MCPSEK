package discovery

// DiscoveredServer represents a server found during discovery
type DiscoveredServer struct {
	Name            string
	SourceURL       string  // GitHub repo URL
	PackageRegistry *string // "npm", "pypi", or nil
	PackageName     *string
	Description     *string
	Author          *string
	License         *string
	Stars           int
}
