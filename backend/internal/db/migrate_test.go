package db

import (
	"testing"
)

func TestSortMigrationsUsesNumericPrefix(t *testing.T) {
	names := []string{"0005_e.sql", "004_d.sql", "0001_a.sql", "003_c.sql", "0002_b.sql", "010_f.sql"}
	sortMigrations(names)
	want := []string{"0001_a.sql", "0002_b.sql", "003_c.sql", "004_d.sql", "0005_e.sql", "010_f.sql"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("order = %v, want %v", names, want)
		}
	}
}
