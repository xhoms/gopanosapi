package gopanosapi

import (
	"encoding/xml"
	"sync"
	"time"
)

const UIDVERSION string = "2.0"
const UIDTYPE string = "update"
const MAXCHANGES int = 100

type groupMemberEntry struct {
	XMLName xml.Name `xml:"entry"`
	Name    string   `xml:"name,attr"`
}

type groupEntry struct {
	XMLName xml.Name           `xml:"entry"`
	Name    string             `xml:"name,attr"`
	Members []groupMemberEntry `xml:"members>entry,omitempty"`
}

type loginEntry struct {
	XMLName xml.Name `xml:"entry"`
	Name    string   `xml:"name,attr"`
	Ip      string   `xml:"ip,attr"`
	Timeout string   `xml:"timeout,attr,omitempty"`
}

type logoutEntry struct {
	XMLName xml.Name `xml:"entry"`
	Name    string   `xml:"name,attr"`
	Ip      string   `xml:"ip,attr"`
}

type payloadElement struct {
	XMLName       xml.Name      `xml:"uid-message"`
	Version       string        `xml:"version"`
	Type          string        `xml:"type"`
	LoginEntries  []loginEntry  `xml:"payload>login>entry,omitempty"`
	LogoutEntries []logoutEntry `xml:"payload>logout>entry,omitempty"`
	GroupEntries  []groupEntry  `xml:"payload>groups>entry,omitempty"`
}

type userPendingEntries struct {
	isLogin           bool
	username, timeout string
}

type UID struct {
	payloadE         payloadElement
	ip2uTransactions map[string]userPendingEntries
	groups           map[string]map[string]struct{}
	device           ApiConnector
	flusher          *sync.Cond
	wg               *sync.WaitGroup
	ticking          *time.Ticker
	flusherQuit      chan struct{}
	tickerQuit       chan struct{}
	cumChanges       int
	dataLock         sync.Mutex
	isRunning        bool
}

func (uid *UID) Init(dev, user, passwd string) error {
	uid.payloadE.Version = UIDVERSION
	uid.payloadE.Type = UIDTYPE
	uid.ip2uTransactions = make(map[string]userPendingEntries)
	uid.groups = make(map[string]map[string]struct{})
	uid.device.Init(dev)
	err := uid.device.Keygen(user, passwd)
	if err != nil {
		return err
	}
	uid.flusher = sync.NewCond(&sync.Mutex{})
	uid.ticking = time.NewTicker(time.Millisecond * 2000)
	uid.wg = &sync.WaitGroup{}
	uid.flusherQuit = make(chan struct{})
	uid.tickerQuit = make(chan struct{})
	uid.wg.Add(2)
	go uid.flushData()
	go uid.tickRcvr()
	uid.isRunning = true
	return nil
}

func (uid *UID) Debug(debug bool) {
	uid.device.Debug(debug)
}

func (uid *UID) IsRunning() bool {
	return uid.isRunning
}

func (uid *UID) Close() {
	if uid.isRunning {
		close(uid.flusherQuit)
		uid.flusher.L.Lock()
		uid.flusher.Signal()
		uid.flusher.L.Unlock()
		close(uid.tickerQuit)
		uid.wg.Wait()
	}
	uid.isRunning = false
}

func (uid *UID) AddLogin(username, ipaddr, timeout string) {
	uid.dataLock.Lock()
	_, ok := uid.ip2uTransactions[ipaddr]
	if ok {
		delete(uid.ip2uTransactions, ipaddr)
		uid.incChange(-1)
	} else {
		uid.ip2uTransactions[ipaddr] = userPendingEntries{isLogin: true, username: username, timeout: timeout}
		uid.incChange(1)
	}
	uid.dataLock.Unlock()
}

func (uid *UID) AddLogout(username, ipaddr string) {
	uid.dataLock.Lock()
	_, ok := uid.ip2uTransactions[ipaddr]
	if ok {
		delete(uid.ip2uTransactions, ipaddr)
		uid.incChange(-1)
	} else {
		uid.ip2uTransactions[ipaddr] = userPendingEntries{isLogin: false, username: username, timeout: ""}
		uid.incChange(1)
	}
	uid.dataLock.Unlock()
}

func (uid *UID) AddGroupMember(group, member string) {
	uid.dataLock.Lock()
	groupId, okg := uid.groups[group]
	if okg {
		_, oku := groupId[member]
		if !oku {
			groupId[member] = struct{}{}
			uid.incChange(1)
		}
	} else {
		uid.groups[group] = make(map[string]struct{})
		uid.groups[group][member] = struct{}{}
		uid.incChange(1)
	}
	uid.dataLock.Unlock()
}

func (uid *UID) RemoveGroupMember(group, member string) {
	uid.dataLock.Lock()
	groupId, okg := uid.groups[group]
	if okg {
		_, oku := groupId[member]
		if oku {
			delete(groupId, member)
			uid.incChange(1)
		}
	}
	uid.dataLock.Unlock()
}

func (uid *UID) gGarbage() {
	for gName, gMembers := range uid.groups {
		if len(gMembers) == 0 {
			delete(uid.groups, gName)
		}
	}
}

func (uid *UID) incChange(increment int) {
	uid.cumChanges += increment
	if uid.cumChanges == MAXCHANGES {
		uid.flusher.L.Lock()
		uid.flusher.Signal()
		uid.flusher.L.Unlock()
	}
}

func (uid *UID) tickRcvr() {
	defer uid.wg.Done()
LEAVE:
	for {
		select {
		case <-uid.ticking.C:
			uid.dataLock.Lock()
			if uid.cumChanges > 0 {
				uid.flusher.L.Lock()
				uid.flusher.Signal()
				uid.flusher.L.Unlock()
			}
			uid.dataLock.Unlock()
		case <-uid.tickerQuit:
			uid.ticking.Stop()
			break LEAVE
		}
	}
}

func (uid *UID) flushData() {
	defer uid.wg.Done()
	for {
		select {
		case <-uid.flusherQuit:
			return
		default:
			uid.flusher.L.Lock()
			uid.flusher.Wait()
			uid.flusher.L.Unlock()
			uid.dataLock.Lock()
			uid.payloadE.LoginEntries = []loginEntry{}
			uid.payloadE.LogoutEntries = []logoutEntry{}
			uid.payloadE.GroupEntries = []groupEntry{}
			// let's prepare login and logout entries
			for ipaddr, uidMap := range uid.ip2uTransactions {
				if uidMap.isLogin {
					uid.payloadE.LoginEntries = append(uid.payloadE.LoginEntries,
						loginEntry{Name: uidMap.username,
							Ip: ipaddr, Timeout: uidMap.timeout})
				} else {
					uid.payloadE.LogoutEntries = append(uid.payloadE.LogoutEntries,
						logoutEntry{Name: uidMap.username, Ip: ipaddr})
				}
			}
			// let's prepare group entries
			for gName, gMembers := range uid.groups {
				newGEntry := groupEntry{Name: gName, Members: []groupMemberEntry{}}
				for mName := range gMembers {
					newGEntry.Members = append(newGEntry.Members, groupMemberEntry{Name: mName})
				}
				uid.payloadE.GroupEntries = append(uid.payloadE.GroupEntries, newGEntry)
			}
			uid.gGarbage()
			uid.ip2uTransactions = make(map[string]userPendingEntries)
			uid.cumChanges = 0
			uid.dataLock.Unlock()
			message, _ := xml.Marshal(&uid.payloadE)
			uid.device.Uid(string(message[:]))
		}
	}
}

func (uid *UID) Marshall() ([]byte, error) {
	return (xml.Marshal(&uid.payloadE))
}
