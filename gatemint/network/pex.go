package network

import (
	"fmt"
	"github.com/gatechain/crypto"
	"github.com/gatechain/gatemint/protocol"
	"time"
)

const maxPexNumber = 20
const maxBackupPhonebookSize = 1000

func pexRequestHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	peer.pexLock.Lock()
	defer peer.pexLock.Unlock()
	wn := message.Net.(*WebsocketNetwork)
	now := time.Now().Unix()
	if time.Duration(now-peer.lastPexRequest)*time.Second >= pexRequestInterval/2 {
		wn.log.Infoln("receive pex request from", peer.rootURL)
		addresses := wn.RandomPickPeersConnectedIn(peer, maxPexNumber)
		if len(addresses) > 0 {
			abytes := protocol.Encode(addresses)
			tbytes := []byte(protocol.PexAddressesTag)
			mbytes := make([]byte, len(tbytes)+len(abytes))
			copy(mbytes, tbytes)
			copy(mbytes[len(tbytes):], abytes)
			peer.writeNonBlock(mbytes, false, crypto.Digest{}, time.Now())
		}
		peer.lastPexRequest = now
	} else {
		wn.log.Infoln("pex requests from", peer.rootURL, "is too often.")
	}
	return OutgoingMessage{}
}

func pexAddressesHandler(message IncomingMessage) OutgoingMessage {
	peer := message.Sender.(*wsPeer)
	peer.pexLock.Lock()
	defer peer.pexLock.Unlock()
	wn := message.Net.(*WebsocketNetwork)
	now := time.Now().Unix()
	if time.Duration(now-peer.lastPexResponse)*time.Second >= pexRequestInterval/2 {
		wn.log.Infoln("receive pex response from", peer.rootURL)
		var addresses []string
		protocol.Decode(message.Data, &addresses)
		if len(addresses) <= maxPexNumber {
			wn.pexAddresses <- addresses
		}
		fmt.Println(addresses)
		peer.lastPexResponse = now
	} else {
		wn.log.Infoln("pex responses from", peer.rootURL, "is too often.")
	}
	return OutgoingMessage{}
}

var pexHandlers = []TaggedMessageHandler{
	TaggedMessageHandler{protocol.PexRequestTag, HandlerFunc(pexRequestHandler)},
	TaggedMessageHandler{protocol.PexAddressesTag, HandlerFunc(pexAddressesHandler)},
}
