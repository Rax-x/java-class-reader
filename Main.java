import java.io.*;

public abstract class Main implements Serializable {
    public static void foo(int x) {  }
    public static void foo(float x) {  }

    private String test = "hello";

    public static void main(String[] args) {
        System.out.println("Hello, World");
        System.out.println(34 + 35);
    }
}