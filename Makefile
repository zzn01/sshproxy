BIN := sshproxy
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64
# Desktop builds: Wails window and tray, without cgo (purego backends).
DESKTOP_TAGS := gui,production,purego
VERSION ?= dev

.PHONY: build desktop test release clean

build:
	go build -o $(BIN) .

# The desktop app for this machine.
desktop:
	CGO_ENABLED=0 go build -tags $(DESKTOP_TAGS) -o $(BIN)-desktop .

test:
	go test -race ./...

# Command line builds plus desktop apps for every platform, all from one
# machine: dist/sshproxy-<os>-<arch>[.exe] and dist/desktop/.
release:
	@mkdir -p dist/desktop
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "dist/$(BIN)-$$os-$$arch$$ext"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "-s -w" \
			-o dist/$(BIN)-$$os-$$arch$$ext . || exit 1; \
	done
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		case $$os in \
		darwin) \
			app=dist/desktop/sshproxy-macos-$$arch/sshproxy.app; echo "$$app"; \
			rm -rf $$app && mkdir -p $$app/Contents/MacOS && \
			sed 's/@VERSION@/$(VERSION)/' packaging/Info.plist > $$app/Contents/Info.plist && \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -tags $(DESKTOP_TAGS) -trimpath -ldflags "-s -w" \
				-o $$app/Contents/MacOS/sshproxy . || exit 1; \
			{ command -v codesign >/dev/null && codesign --force --deep -s - $$app; true; } && \
			(cd dist/desktop/sshproxy-macos-$$arch && zip -qry ../sshproxy-macos-$$arch.zip sshproxy.app) ;; \
		windows) \
			echo "dist/desktop/sshproxy-windows-$$arch.exe"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -tags $(DESKTOP_TAGS) -trimpath -ldflags "-s -w -H windowsgui" \
				-o dist/desktop/sshproxy-windows-$$arch.exe . || exit 1 ;; \
		linux) \
			echo "dist/desktop/sshproxy-linux-$$arch"; \
			CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -tags $(DESKTOP_TAGS) -trimpath -ldflags "-s -w" \
				-o dist/desktop/sshproxy-linux-$$arch . || exit 1 ;; \
		esac; \
	done

clean:
	rm -rf $(BIN) $(BIN)-desktop dist
