// Package searchtrie provides a simple trie structure to match binary data
package trie

// node is a node in the trie
type node[T any] struct {
	children map[byte]*node[T]
	value    T
	hasValue bool // Needed to distinguish between zero value and no value
}

// newNode returns a new node
func newNode[T any]() *node[T] {
	return &node[T]{
		children: make(map[byte]*node[T]),
		hasValue: false,
	}
}

// Trie represents a search trie for pattern matching
type Trie[T any] struct {
	root *node[T]
}

// NewTrie returns a new trie for pattern matching
func NewTrie[T any]() *Trie[T] {
	return &Trie[T]{
		root: newNode[T](),
	}
}

// Insert adds an entry into the trie based on the given key pattern
func (t *Trie[T]) Insert(key []byte, value T) {
	if len(key) == 0 {
		return
	}

	current := t.root
	for _, b := range key {
		child, exists := current.children[b]
		if !exists {
			child = newNode[T]()
			current.children[b] = child
		}
		current = child
	}
	current.value = value
	current.hasValue = true
}

// Match searches the data for patterns previously inserted into the trie.
// It returns the value associated with the longest matching pattern and a bool
// indicating if a match was found.
func (t *Trie[T]) Match(data []byte) (T, bool) {
	var zeroValue T
	var bestMatch T
	found := false

	// Search the first N bytes for matches
	maxSearchLen := 25
	dataLen := len(data)
	if dataLen < maxSearchLen {
		maxSearchLen = dataLen
	}

	// Try matching from each starting position
	for startPos := 0; startPos < maxSearchLen; startPos++ {
		current := t.root
		matchFound := false

		// Try to match from this position
		for _, b := range data[startPos:] {
			child, exists := current.children[b]
			if !exists {
				break // No match for this path
			}

			current = child

			// If we found a value, remember it
			if current.hasValue {
				bestMatch = current.value
				found = true
				matchFound = true
			}
		}

		// If we found a match at this position, return it immediately
		// This is a greedy algorithm - first match wins
		if matchFound {
			return bestMatch, true
		}
	}

	if found {
		return bestMatch, true
	}
	return zeroValue, false
}

// MatchExact returns the value for an exact key match and a bool indicating if found
func (t *Trie[T]) MatchExact(key []byte) (T, bool) {
	var zeroValue T
	current := t.root

	for _, b := range key {
		child, exists := current.children[b]
		if !exists {
			return zeroValue, false
		}
		current = child
	}

	if current.hasValue {
		return current.value, true
	}
	return zeroValue, false
}

// Delete removes an entry with the exact key from the trie
// Returns true if the key was found and removed, false otherwise
func (t *Trie[T]) Delete(key []byte) bool {
	if len(key) == 0 {
		return false
	}

	// Need to track the path to properly clean up empty nodes
	path := make([]*node[T], len(key)+1)
	path[0] = t.root

	// Find the node
	current := t.root
	for i, b := range key {
		child, exists := current.children[b]
		if !exists {
			return false // Key not found
		}
		path[i+1] = child
		current = child
	}

	// Check if we found a value
	if !current.hasValue {
		return false
	}

	// Remove the value
	var zeroValue T
	current.value = zeroValue
	current.hasValue = false

	// Clean up empty nodes (optional)
	for i := len(key); i > 0; i-- {
		node := path[i]
		if len(node.children) > 0 || node.hasValue {
			break // Node still used
		}
		parent := path[i-1]
		delete(parent.children, key[i-1])
	}

	return true
}

// Clear removes all entries from the trie
func (t *Trie[T]) Clear() {
	t.root = newNode[T]()
}

// Count returns the number of values stored in the trie
func (t *Trie[T]) Count() int {
	count := 0

	// Helper to traverse the trie
	var countNodes func(*node[T])
	countNodes = func(n *node[T]) {
		if n.hasValue {
			count++
		}
		for _, child := range n.children {
			countNodes(child)
		}
	}

	countNodes(t.root)
	return count
}

// Keys returns all the keys in the trie
func (t *Trie[T]) Keys() [][]byte {
	var keys [][]byte

	// Helper for traversal
	var traverse func(*node[T], []byte)
	traverse = func(n *node[T], prefix []byte) {
		if n.hasValue {
			keys = append(keys, append([]byte{}, prefix...))
		}

		for b, child := range n.children {
			newPrefix := append(prefix, b)
			traverse(child, newPrefix)
		}
	}

	traverse(t.root, []byte{})
	return keys
}
