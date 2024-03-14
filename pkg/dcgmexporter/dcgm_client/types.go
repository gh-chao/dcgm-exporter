/*
 * Copyright (c) 2021, NVIDIA CORPORATION.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//go:generate mockgen -destination=mocks/pkg/dcgmexporter/dcgm_client/mock_client.go github.com/NVIDIA/dcgm-exporter/pkg/dcgmexporter/dcgm_client DCGMClient

package dcgm_client

import (
	"time"

	"github.com/NVIDIA/go-dcgm/pkg/dcgm"
)

type DCGMClient interface {
	AddEntityToGroup(dcgm.GroupHandle, dcgm.Field_Entity_Group, uint) error
	AddLinkEntityToGroup(dcgm.GroupHandle, uint, uint) error
	CreateGroup(string) (dcgm.GroupHandle, error)
	DestroyGroup(groupId dcgm.GroupHandle) error
	EntitiesGetLatestValues([]dcgm.GroupEntityPair, []dcgm.Short, uint) ([]dcgm.FieldValue_v2, error)
	EntityGetLatestValues(dcgm.Field_Entity_Group, uint, []dcgm.Short) ([]dcgm.FieldValue_v1, error)
	FieldGetById(dcgm.Short) dcgm.FieldMeta
	FieldGroupCreate(string, []dcgm.Short) (dcgm.FieldHandle, error)
	FieldGroupDestroy(dcgm.FieldHandle) error
	GetAllDeviceCount() (uint, error)
	GetCpuHierarchy() (dcgm.CpuHierarchy_v1, error)
	GetDeviceInfo(uint) (dcgm.Device, error)
	GetEntityGroupEntities(entityGroup dcgm.Field_Entity_Group) ([]uint, error)
	GetGpuInstanceHierarchy() (dcgm.MigHierarchy_v2, error)
	GetNvLinkLinkStatus() ([]dcgm.NvLinkStatus, error)
	GetSupportedDevices() ([]uint, error)
	GetSupportedMetricGroups(uint) ([]dcgm.MetricGroup, error)
	GetValuesSince(dcgm.GroupHandle, dcgm.FieldHandle, time.Time) ([]dcgm.FieldValue_v2, time.Time, error)
	GroupAllGPUs() dcgm.GroupHandle
	LinkGetLatestValues(uint, uint, []dcgm.Short) ([]dcgm.FieldValue_v1, error)
	NewDefaultGroup(string) (dcgm.GroupHandle, error)
	UpdateAllFields() error
	WatchFieldsWithGroupEx(dcgm.FieldHandle, dcgm.GroupHandle, int64, float64, int32) error
	Cleanup()
}