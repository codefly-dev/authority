module github.com/codefly-dev/authority/libraries/authority-core/go

go 1.27.3

require (
	github.com/codefly-dev/authority/libraries/resources/go v0.0.0
	github.com/codefly-dev/core v0.19.7-0.20261026022918-8af4b787a435
	google.golang.org/protobuf v1.36.12
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.12-20260825204119-511051f7f437.2 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
)

replace github.com/codefly-dev/authority/libraries/resources/go => ../../resources/go
