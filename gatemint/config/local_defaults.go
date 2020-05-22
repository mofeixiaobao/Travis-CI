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

package config

import (
	"fmt"
	"time"
)

var defaultLocal = defaultLocalV1

const configVersion = uint32(1)

// !!! WARNING !!!
//
// These versioned structures need to be maintained CAREFULLY and treated
// like UNIVERSAL CONSTANTS - they should not be modified once committed.
//
// New fields may be added to the current defaultLocalV# and should
// also be added to installer/config.json.example and
// test/testdata/configs/config-v{n}.json
//
// Changing a default value requires creating a new defaultLocalV# instance,
// bump the version number (configVersion), and add appropriate migration and tests.
//
// !!! WARNING !!!

var defaultLocalV1 = Local{
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
	Version:                               1,
	Archival:                              false,
	BaseLoggerDebugLevel:                  4, // Was 1
	BroadcastConnectionsLimit:             -1,
	AnnounceParticipationKey:              true,
	PriorityPeers:                         map[string]bool{},
	CadaverSizeTarget:                     1073741824,
	CatchupFailurePeerRefreshRate:         10,
	CatchupParallelBlocks:                 50,
	ConnectionsRateLimitingCount:          60,
	ConnectionsRateLimitingWindowSeconds:  1,
	DeadlockDetection:                     0,
	DNSBootstrapID:                        "<network>.algorand.network",
	EnableAgreementReporting:              false,
	EnableAgreementTimeMetrics:            false,
	EnableIncomingMessageFilter:           false,
	EnableMetricReporting:                 false,
	EnableOutgoingNetworkMessageFiltering: true,
	EnableRequestLogger:                   false,
	EnableTopAccountsReporting:            false,
	EndpointAddress:                       "127.0.0.1:0",
	GossipFanout:                          4,
	IsSRV:                                 true,
	IncomingConnectionsLimit:              10000, // Was -1
	IncomingMessageFilterBucketCount:      5,
	IncomingMessageFilterBucketSize:       512,
	LogArchiveName:                        "node.archive.log",
	LogArchiveMaxAge:                      "",
	LogSizeLimit:                          1073741824,
	MaxConnectionsPerIP:                   30,
	NetAddress:                            "",
	NodeExporterListenAddress:             ":9100",
	NodeExporterPath:                      "./node_exporter",
	OutgoingMessageFilterBucketCount:      3,
	OutgoingMessageFilterBucketSize:       128,
	ReconnectTime:                         1 * time.Minute, // Was 60ns
	ReservedFDs:                           256,
	RestReadTimeoutSeconds:                15,
	RestWriteTimeoutSeconds:               120,
	RunHosted:                             false,
	SuggestedFeeBlockHistory:              3,
	SuggestedFeeSlidingWindowSize:         50,
	TxSortedType:                          0,
	TxPoolExponentialIncreaseFactor:       2,
	TxPoolSize:                            15000,
	TxSyncIntervalSeconds:                 60,
	TxSyncTimeoutSeconds:                  30,
	TxSyncServeResponseSize:               1000000,
	FirstPartKeyRound:                     0,
	LastPartKeyRound:                      300000000,
	RefreshPartInterval:                   2,
	MinimumTxFee:						   10,
	// DO NOT MODIFY VALUES - New values may be added carefully - See WARNING at top of file
}

func migrate(cfg Local) (newCfg Local, err error) {
	newCfg = cfg
	if cfg.Version == configVersion {
		return
	}

	if cfg.Version > configVersion {
		err = fmt.Errorf("unexpected config version: %d", cfg.Version)
		return
	}

	if newCfg.Version != configVersion {
		err = fmt.Errorf("failed to migrate config version %d (stuck at %d) to latest %d", cfg.Version, newCfg.Version, configVersion)
	}

	// Migrate 0 -> 1
	if newCfg.Version == 0 {
		newCfg.Version = 1
	}

	return
}
