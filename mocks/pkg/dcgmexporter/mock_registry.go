// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/NVIDIA/dcgm-exporter/pkg/dcgmexporter (interfaces: RegistryInterface)
//
// Generated by this command:
//
//	mockgen -destination=mocks/pkg/dcgmexporter/mock_registry.go github.com/NVIDIA/dcgm-exporter/pkg/dcgmexporter RegistryInterface
//

// Package mock_dcgmexporter is a generated GoMock package.
package mock_dcgmexporter

import (
	reflect "reflect"

	dcgmexporter "github.com/NVIDIA/dcgm-exporter/pkg/dcgmexporter"
	gomock "go.uber.org/mock/gomock"
)

// MockRegistryInterface is a mock of RegistryInterface interface.
type MockRegistryInterface struct {
	ctrl     *gomock.Controller
	recorder *MockRegistryInterfaceMockRecorder
}

// MockRegistryInterfaceMockRecorder is the mock recorder for MockRegistryInterface.
type MockRegistryInterfaceMockRecorder struct {
	mock *MockRegistryInterface
}

// NewMockRegistryInterface creates a new mock instance.
func NewMockRegistryInterface(ctrl *gomock.Controller) *MockRegistryInterface {
	mock := &MockRegistryInterface{ctrl: ctrl}
	mock.recorder = &MockRegistryInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockRegistryInterface) EXPECT() *MockRegistryInterfaceMockRecorder {
	return m.recorder
}

// Cleanup mocks base method.
func (m *MockRegistryInterface) Cleanup() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Cleanup")
}

// Cleanup indicates an expected call of Cleanup.
func (mr *MockRegistryInterfaceMockRecorder) Cleanup() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Cleanup", reflect.TypeOf((*MockRegistryInterface)(nil).Cleanup))
}

// Gather mocks base method.
func (m *MockRegistryInterface) Gather() (dcgmexporter.MetricsByCounter, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Gather")
	ret0, _ := ret[0].(dcgmexporter.MetricsByCounter)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Gather indicates an expected call of Gather.
func (mr *MockRegistryInterfaceMockRecorder) Gather() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Gather", reflect.TypeOf((*MockRegistryInterface)(nil).Gather))
}

// Register mocks base method.
func (m *MockRegistryInterface) Register(arg0 dcgmexporter.Collector) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Register", arg0)
}

// Register indicates an expected call of Register.
func (mr *MockRegistryInterfaceMockRecorder) Register(arg0 any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Register", reflect.TypeOf((*MockRegistryInterface)(nil).Register), arg0)
}