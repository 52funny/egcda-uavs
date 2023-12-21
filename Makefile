.PHONY: build cp

OUT_DIR := ./bin

build:
	cargo build -r

cp:
	@if [ ! -d "$(OUT_DIR)" ]; then \
		mkdir -p "$(OUT_DIR)"; \
	fi
	cp target/release/ta ${OUT_DIR}/ta
	cp target/release/gs ${OUT_DIR}/gs
	cp target/release/uav ${OUT_DIR}/uav
	strip ${OUT_DIR}/ta
	strip ${OUT_DIR}/gs
	strip ${OUT_DIR}/uav

