#!/usr/bin/env bash
mvn package
java -cp target/ezejavagoat-1.0-SNAPSHOT.jar com.riversafe.ezejavagoat.App
