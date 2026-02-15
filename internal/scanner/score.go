package scanner

// ComputeTrustScore calculates the trust score based on three check results
// Score starts at 100 and subtracts penalties
func ComputeTrustScore(integrity, auth, exposure string) int {
	score := 100

	// Check 1: Tool Integrity
	switch integrity {
	case "critical":
		score -= 50
	case "warning":
		score -= 15
	}

	// Check 2: Authentication Posture
	switch auth {
	case "critical":
		score -= 35
	case "warning":
		score -= 15
	}

	// Check 3: Endpoint Exposure
	switch exposure {
	case "critical":
		score -= 30
	case "warning":
		score -= 10
	}

	// Floor at 0, cap at 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
