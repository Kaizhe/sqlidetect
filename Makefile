.PHONY: all

all: deps test build

deps:
	@echo "+ $@"
	./scripts/deps
test:
	@echo "+ $@"
	./scripts/test
build:
	@echo "+ $@"
	./scripts/build

