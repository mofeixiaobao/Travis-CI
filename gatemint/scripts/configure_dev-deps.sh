#!/usr/bin/env bash

set -ex

function install_go_module {
    local OUTPUT
    OUTPUT=$(GO111MODULE=off go get -u $1 2>&1)
    if [ "${OUTPUT}" != "" ]; then
        echo "error: executing \"go get -u $1\" failed : ${OUTPUT}"
        exit 1
    fi
}

#install_go_module golang.org/x/lint/golint
#install_go_module golang.org/x/tools/cmd/stringer
#install_go_module github.com/go-swagger/go-swagger/cmd/swagger

echo "golang.org/x/lint/golint"
$(git clone https://github.com/golang/lint.git golang.org/x/lint)
$(go install golang.org/x/lint/golint)

echo "golang.org/x/tools/cmd/stringer"
$(git clone https://github.com/golang/tools.git golang.org/x/tools)
$(go install golang.org/x/tools/cmd/stringer)

echo "github.com/go-swagger/go-swagger/cmd/swagger"
$(git clone https://github.com/go-swagger/go-swagger.git github.com/go-swagger/go-swagger)
$(go install github.com/go-swagger/go-swagger/cmd/swagger)