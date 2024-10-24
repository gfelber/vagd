build: clean
	@ if [ "${VIRTUAL_ENV}" = "" ]; then \
		source ./venv/bin/activate; \
	fi; \
	python3 -m build;

publish: build
	@ if [ "${VIRTUAL_ENV}" = "" ]; then \
		source ./venv/bin/activate; \
	fi; \
	python3 -m twine check dist/*; \
	python3 -m twine upload --repository pypi dist/*;

.PHONY: test
test :
	@ if [ "${VIRTUAL_ENV}" = "" ]; then \
		source ./venv/bin/activate; \
	fi; \
	cd test; \
	mkdir -p bin; \
	gcc sysinfo.c -o bin/sysinfo; \
	gcc sysinfo.c -static -o bin/sysinfo_stat; \
	vagd clean; \
	echo STARTING TEST; \
	if python ./test.py GDB; then \
		echo "successful"; \
	else \
		echo "test unsuccessful, pls fix"; \
	fi;

clean:
	rm -r build dist src/*.egg-info || true;
