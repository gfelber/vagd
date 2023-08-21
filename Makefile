build: clean
	python3 -m build

publish: build
	python3 -m twine check dist/*
	python3 -m twine upload --repository pypi dist/*

clean:
	rm -r build dist src/*.egg-info || true
