package authlib

// containsString returns true if the provided value is in the provided slice
func containsString(slice []string, val string) bool {
	for _, v := range slice {
		if val == v {
			return true
		}
	}
	return false
}
