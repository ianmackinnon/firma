SHELL := /bin/bash

NAME := firma

all :

clean : clean-packages clean-python-cache

build-packages :
	python3 setup.py sdist bdist_wheel

clean-packages :
	rm -rf .eggs build dist $(NAME).egg-info

clean-python-cache :
	find . -name __pycache__ -exec rm -rf {} +

get-version :
	@python3 -c "import firma; print(firma.version.__version__)"

set-version :
ifeq ($(V),)
	@echo "Version variable \`V\` is not set." 1>&2
	@false
else
	echo "__version__ = \"$(V)\"" > firma/version.py; git add firma/version.py;
endif

tag-version :
ifeq ($(V),)
	@echo "Version variable \`V\` is not set." 1>&2
	@false
else
	git tag -m "v${V}" -a "v${V}" -f
endif
