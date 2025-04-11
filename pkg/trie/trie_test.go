package trie

import (
	"reflect"
	"testing"
)

func TestNewTrie(t *testing.T) {
	trie := NewTrie[string]()
	if trie == nil {
		t.Fatal("Expected new trie to not be nil")
	}
	if trie.root == nil {
		t.Fatal("Expected new trie to have a root node")
	}
}

func TestInsert(t *testing.T) {
	trie := NewTrie[string]()

	// Test basic insert
	trie.Insert([]byte("test"), "value")

	// Test empty key (should be ignored)
	trie.Insert([]byte{}, "empty")

	// Verify through MatchExact
	if val, found := trie.MatchExact([]byte("test")); !found || val != "value" {
		t.Errorf("Expected to find 'value' for 'test', got %v, found: %v", val, found)
	}

	// Empty key should not be found
	if _, found := trie.MatchExact([]byte{}); found {
		t.Error("Empty key should not be inserted or found")
	}

	// Test overwrite
	trie.Insert([]byte("test"), "new value")
	if val, found := trie.MatchExact([]byte("test")); !found || val != "new value" {
		t.Errorf("Expected to find 'new value' after overwrite, got %v", val)
	}
}

func TestMatch(t *testing.T) {
	trie := NewTrie[string]()

	// Insert some patterns
	trie.Insert([]byte("HTTP"), "http")
	trie.Insert([]byte("GET"), "get")
	trie.Insert([]byte("POST"), "post")
	trie.Insert([]byte("SSH"), "ssh")

	// Test basic match
	if val, found := trie.Match([]byte("HTTP/1.1")); !found || val != "http" {
		t.Errorf("Expected to match 'http' in 'HTTP/1.1', got %v, found: %v", val, found)
	}

	// Test match at different position
	if val, found := trie.Match([]byte("XGET ")); !found || val != "get" {
		t.Errorf("Expected to match 'get' in 'XGET ', got %v, found: %v", val, found)
	}

	// Test multiple possible matches (first match should win)
	// INSERT <SSH> should match SSH, not HTTP
	if val, found := trie.Match([]byte("INSERT SSH HERE")); !found || val != "ssh" {
		t.Errorf("Expected to match 'ssh' in 'INSERT SSH HERE', got %v, found: %v", val, found)
	}

	// Test no match
	if _, found := trie.Match([]byte("UNKNOWN")); found {
		t.Error("Expected no match for 'UNKNOWN'")
	}

	// Test match with empty trie
	emptyTrie := NewTrie[string]()
	if _, found := emptyTrie.Match([]byte("any data")); found {
		t.Error("Expected no match in empty trie")
	}

	// Test matching large data (beyond 25 byte limit)
	largeData := make([]byte, 100)
	copy(largeData[30:], []byte("HTTP"))
	if _, found := trie.Match(largeData); found {
		t.Error("Expected no match beyond 25 byte limit")
	}
}

func TestMatchExact(t *testing.T) {
	trie := NewTrie[int]()

	// Insert some patterns
	trie.Insert([]byte("apple"), 1)
	trie.Insert([]byte("app"), 2)
	trie.Insert([]byte("banana"), 3)

	// Test exact match
	if val, found := trie.MatchExact([]byte("apple")); !found || val != 1 {
		t.Errorf("Expected to match exactly 1 for 'apple', got %v, found: %v", val, found)
	}

	// Test prefix (should not match)
	if _, found := trie.MatchExact([]byte("ap")); found {
		t.Error("Expected no match for prefix 'ap'")
	}

	// Test extension (should not match)
	if _, found := trie.MatchExact([]byte("applejuice")); found {
		t.Error("Expected no match for extension 'applejuice'")
	}

	// Test no match
	if _, found := trie.MatchExact([]byte("orange")); found {
		t.Error("Expected no match for 'orange'")
	}
}

func TestDelete(t *testing.T) {
	trie := NewTrie[string]()

	// Insert some data
	trie.Insert([]byte("key1"), "value1")
	trie.Insert([]byte("key2"), "value2")
	trie.Insert([]byte("keyprefix"), "prefix")

	// Test successful delete
	if !trie.Delete([]byte("key1")) {
		t.Error("Delete should return true for existing key")
	}

	// Verify key was deleted
	if _, found := trie.MatchExact([]byte("key1")); found {
		t.Error("Expected key1 to be deleted")
	}

	// Test key2 still exists
	if _, found := trie.MatchExact([]byte("key2")); !found {
		t.Error("Expected key2 to still exist")
	}

	// Test delete non-existent key
	if trie.Delete([]byte("nonexistent")) {
		t.Error("Delete should return false for non-existent key")
	}

	// Test delete empty key
	if trie.Delete([]byte{}) {
		t.Error("Delete should return false for empty key")
	}

	// Test node cleanup after delete
	trie.Delete([]byte("key2"))
	trie.Delete([]byte("keyprefix"))
	// After deleting all keys, the trie should be empty except for the root
	if len(trie.root.children) != 0 {
		t.Error("Expected trie to be empty after deleting all keys")
	}
}

func TestClear(t *testing.T) {
	trie := NewTrie[string]()

	// Insert some data
	trie.Insert([]byte("key1"), "value1")
	trie.Insert([]byte("key2"), "value2")

	// Clear the trie
	trie.Clear()

	// Verify trie is empty
	if _, found := trie.MatchExact([]byte("key1")); found {
		t.Error("Expected key1 to be deleted after Clear")
	}
	if _, found := trie.MatchExact([]byte("key2")); found {
		t.Error("Expected key2 to be deleted after Clear")
	}
	if len(trie.root.children) != 0 {
		t.Error("Expected trie to have empty root children after Clear")
	}
}

func TestCount(t *testing.T) {
	trie := NewTrie[string]()

	// Empty trie should have count 0
	if count := trie.Count(); count != 0 {
		t.Errorf("Expected empty trie to have count 0, got %d", count)
	}

	// Insert some data
	trie.Insert([]byte("key1"), "value1")
	trie.Insert([]byte("key2"), "value2")

	// Check count
	if count := trie.Count(); count != 2 {
		t.Errorf("Expected count 2 after two inserts, got %d", count)
	}

	// Insert duplicate key (overwrite)
	trie.Insert([]byte("key1"), "new value")
	if count := trie.Count(); count != 2 {
		t.Errorf("Expected count to remain 2 after overwrite, got %d", count)
	}

	// Delete a key
	trie.Delete([]byte("key1"))
	if count := trie.Count(); count != 1 {
		t.Errorf("Expected count 1 after delete, got %d", count)
	}

	// Clear the trie
	trie.Clear()
	if count := trie.Count(); count != 0 {
		t.Errorf("Expected count 0 after clear, got %d", count)
	}
}

func TestKeys(t *testing.T) {
	trie := NewTrie[string]()

	// Empty trie should return empty keys slice
	if keys := trie.Keys(); len(keys) != 0 {
		t.Errorf("Expected empty trie to have no keys, got %v", keys)
	}

	// Insert some keys
	testKeys := [][]byte{
		[]byte("apple"),
		[]byte("app"),
		[]byte("banana"),
	}

	for _, key := range testKeys {
		trie.Insert(key, string(key))
	}

	// Get keys
	keys := trie.Keys()

	// Check if we have the right number of keys
	if len(keys) != len(testKeys) {
		t.Errorf("Expected %d keys, got %d: %v", len(testKeys), len(keys), keys)
	}

	// Check if all keys are present
	// Convert [][]byte to map for easier checking
	keyMap := make(map[string]bool)
	for _, key := range keys {
		keyMap[string(key)] = true
	}

	for _, key := range testKeys {
		if !keyMap[string(key)] {
			t.Errorf("Expected key %s in Keys() result but not found", string(key))
		}
	}
}

func TestDifferentTypes(t *testing.T) {
	// Test with int
	intTrie := NewTrie[int]()
	intTrie.Insert([]byte("one"), 1)
	intTrie.Insert([]byte("two"), 2)

	if val, found := intTrie.MatchExact([]byte("one")); !found || val != 1 {
		t.Errorf("Expected to find int value 1, got %v", val)
	}

	// Test with struct
	type Person struct {
		Name string
		Age  int
	}

	personTrie := NewTrie[Person]()
	personTrie.Insert([]byte("alice"), Person{Name: "Alice", Age: 30})

	if val, found := personTrie.MatchExact([]byte("alice")); !found || val.Name != "Alice" || val.Age != 30 {
		t.Errorf("Expected to find Person{Alice, 30}, got %v", val)
	}

	// Test with slice
	sliceTrie := NewTrie[[]string]()
	sliceTrie.Insert([]byte("fruits"), []string{"apple", "banana"})

	if val, found := sliceTrie.MatchExact([]byte("fruits")); !found || !reflect.DeepEqual(val, []string{"apple", "banana"}) {
		t.Errorf("Expected to find []string{apple, banana}, got %v", val)
	}
}
