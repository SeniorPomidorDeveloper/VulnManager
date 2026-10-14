package normalizers

func StandardPathRules() (PathRules, error) {
	return NewPathRules([]string{
		"/home/runner/work/*/*/",
		"/github/workspace/",
		"/builds/*/*/",
		"/workspace/",
		"/src/",
		"/app/",
	})
}
