package contrive

import (
	"encoding/json"
	"log"
	"strconv"
	"time"
)

// NewRecentClient creates a new client for recent messages
func (c *Contrive) NewRecentClient() chan []byte {
	nc := make(chan []byte, 200)
	c.recentClients = append(c.recentClients, nc)
	return nc
}

// Send	a message to the channel
func Send(c chan []byte, t []byte) (ok bool) {
	defer func() { recover() }()
	c <- t
	return true
}

func (c *Contrive) recentPump() {
	ignoreMessages := make(map[string]time.Time)
	for {
		time.Sleep(time.Second / 15)
		data, err := c.ESQ.RecentWS()
		if err != nil {
			log.Println(err)
			continue
		}
		if len(data) > 0 {
			for _, frame := range data {
				var key string
				if len(frame.UUID) > 0 {
					key += frame.UUID[0]
				}
				if len(frame.Sequence) > 0 {
					key += strconv.Itoa(frame.Sequence[0])
				}
				if len(frame.Message) > 0 {
					key += frame.Message[0]
				}

				if _, ok := ignoreMessages[key]; !ok {
					b, err := json.Marshal(frame)
					if err != nil {
						log.Println(err)
						continue
					}

					y := c.recentClients[:0]
					for _, ch := range c.recentClients {
						if Send(ch, b) {
							y = append(y, ch)
						}
					}
					c.recentClients = y

					ignoreMessages[key] = time.Now()
				}
			}
		}
		for k, t := range ignoreMessages {
			if time.Since(t) > time.Second*15 {
				delete(ignoreMessages, k)
			}
		}
	}
}
