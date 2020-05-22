// Copyright (C) 2019 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package main

const (
	// General
	errorNoDataDirectory = "Data directory not specified.  Please use -d or set $GATEMINT_DATA in your environment. Exiting."

	// Node
	infoNodeStart               = "Gatemint node successfully started!"
	infoNodeAlreadyStarted      = "Gatemint node was already started!"
	infoTryingToStopNode        = "Trying to stop the node..."
	infoNodeSuccessfullyStopped = "The node was successfully stopped."
	infoNodeStatus              = "Last committed block: %d\nTime since last block: %s\nSync Time: %s\nLast consensus protocol: %s\nNext consensus protocol: %s\nRound for next consensus protocol: %d\nNext consensus protocol supported: %v\nHas Synced Since Startup: %t"
	errorNodeStatus             = "Cannot contact Gatemint node: %s."
	errorNodeFailedToStart      = "Gatemint node failed to start: %s"
	errorKill                   = "Cannot kill node: %s"
	infoDataDir                 = "[Data Directory: %s]"
	errLoadingConfig            = "Error loading Config file from '%s': %v"
	infoNetworkAlreadyExists    = "Network Root Directory '%s' already exists"
	errorCreateNetwork          = "Error creating private network: %s"
	infoNetworkCreated          = "Network %s created under %s"
	errorLoadingNetwork         = "Error loading deployed network: %s"
	errorStartingNetwork        = "Error starting deployed network: %s"
	infoNetworkStarted          = "Network Started under %s"
	infoNetworkStopped          = "Network Stopped under %s"
	infoNetworkDeleted          = "Network Deleted under %s"
)
