build: clean
	python3 -m build

publish: build
	python3 -m twine check dist/*
	python3 -m twine upload --repository pypi dist/*

.PHONY: test
test :
	@ if [ "${VIRTUAL_ENV}" = "" ]; then \
		source ./venv/bin/activate; \
	fi; \
	cd test; \
	VAGRANT_CWD=.vagd vagrant halt; \
	kill $(pgrep qemu); \
	echo STARTING TEST; \
	python ./test.py GDB;

clean:
	rm -r build dist src/*.egg-info || true
