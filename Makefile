lint:
	./node_modules/.bin/standard --fix src test

test: lint
	NODE_OPTIONS=--experimental-vm-modules ./node_modules/.bin/jest
