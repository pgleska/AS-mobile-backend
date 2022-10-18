app:
	rm -rf ./build
	rm -f ./docker/as-mob-backend.jar
	./gradlew build -x test
	cp -f ./build/libs/as-mob-backend.jar ./docker