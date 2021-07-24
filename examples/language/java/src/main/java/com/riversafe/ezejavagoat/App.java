package com.riversafe.ezejavagoat;

import com.github.pwittchen.kirai.library.Kirai;
/**
 * Hello world!
 */
public class App {
    public static void main(String[] args) {
        System.out.println("Hello World!");

        // sanity include to appear in sbom
        CharSequence formatted = Kirai
                .from("My name is Elder {surname_name}\n" +
                        "And I would like to share with you\n" +
                        "The most amazing book")
                .put("surname_name", "Foo")
                .format();
        System.out.println(formatted);
    }
}
