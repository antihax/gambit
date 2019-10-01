// Package searchtree provides a simple tree structure to match binary data
package searchtree

type Node struct {
	Nodes map[byte]*Node
	Entry interface{}
}

func NewNode() *Node {
	return &Node{
		Nodes: make(map[byte]*Node),
	}
}

// Tree represents a search tree for pattern matching
type Tree struct {
	Node *Node
}

// NewTree returns a new tree
func NewTree() Tree {
	return Tree{
		Node: NewNode(),
	}
}

// Insert an entry into the tree
func (s *Tree) Insert(key []byte, value interface{}) {
	lastNode := s.Node
	for _, b := range key {
		n, ok := lastNode.Nodes[b]
		if !ok {
			lastNode.Nodes[b] = NewNode()
			n = lastNode.Nodes[b]
		}
		lastNode = n
	}
	lastNode.Entry = value
}

// Match data to an entry and continue to look ahead in case there are more complex matches
func (s *Tree) Match(data []byte) interface{} {
	var lastSuccess interface{}

	// Search the first 25 bytes for matches
	for i := 0; i < 25; i++ {
		lastNode := s.Node

		for _, b := range data[i:] {
			n, ok := lastNode.Nodes[b]
			// Did we fall of the end of the branch?
			if !ok {
				break // a leg
			}
			lastNode = n

			// Save any successfull entries
			if n.Entry != nil {
				lastSuccess = n.Entry
			}
		}

		if lastSuccess != nil {
			return lastSuccess
		}
	}
	return lastSuccess
}
