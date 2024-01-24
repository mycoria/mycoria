package router

// TODO: Unit test announce ping. Requires quite some setup to do.

// func TestAnnouncePing(t *testing.T) {

// }

// FakePeer delivers the frame to the next router directly.
// type FakePeer struct {
// }

// func getTestRouter(t *testing.T) *Router {
// 	t.Helper()

// 	id, _, err := m.GeneratePrivacyAddress(context.Background())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	instance := &testInstance{
// 		VersionStub:      "v0.0.0",
// 		ConfigStub:       &config.Config{},
// 		IdentityStub:     id,
// 		FrameBuilderStub: frame.NewFrameBuilder(),
// 	}
// 	stateMgr := state.New(instance, nil)
// 	instance.StateStub = stateMgr
// 	router, err := New(instance, Config{})
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	instance.RouterStub = router

// 	return router
// }

// type testInstance testutil.Instance

// var _ instance = &testInstance{}

// // Version returns the version.
// func (stub *testInstance) Version() string {
// 	return stub.VersionStub
// }

// // Config returns the config.
// func (stub *testInstance) Config() *config.Config {
// 	return stub.ConfigStub
// }

// // Identity returns the identity.
// func (stub *testInstance) Identity() *m.Address {
// 	return stub.IdentityStub
// }

// // State returns the state manager.
// func (stub *testInstance) State() *state.State {
// 	return stub.StateStub
// }

// // TunDevice returns the tun device.
// func (stub *testInstance) TunDevice() *tun.Device {
// 	return stub.TunDeviceStub.(*tun.Device)
// }

// // API returns the api.
// func (stub *testInstance) API() *api.API {
// 	return stub.APIStub.(*api.API)
// }

// // FrameBuilder returns the frame builder.
// func (stub *testInstance) FrameBuilder() *frame.Builder {
// 	return stub.FrameBuilderStub.(*frame.Builder)
// }

// // Peering returns the peering manager.
// func (stub *testInstance) Peering() *peering.Peering {
// 	return stub.PeeringStub.(*peering.Peering)
// }

// // Switch returns the switch.
// func (stub *testInstance) Switch() *switchr.Switch {
// 	return stub.SwitchStub.(*switchr.Switch)
// }

// // Router returns the router.
// func (stub *testInstance) Router() *Router {
// 	return stub.RouterStub.(*Router)
// }

// // RoutingTable returns the routing table.
// func (stub *testInstance) RoutingTable() *m.RoutingTable {
// 	return stub.RouterStub.(*Router).Table()
// }
