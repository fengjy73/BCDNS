package org.bcdns.credential.common.utils;


import java.util.UUID;

public class IdGenerator {
    public IdGenerator() {
    }

    public static String createApplyNo() {
        String uuid = UUID.randomUUID().toString();
        String hashString = Encrypt.SHA256(uuid);
        return hashString.substring(hashString.length() - 32, hashString.length());
    }

    public static String createApplyNo(String oldApplyNo) {
        String hashString = Encrypt.SHA256(oldApplyNo);
        return hashString.substring(hashString.length() - 32, hashString.length());
    }

    private static String getUUID() {
        String s = UUID.randomUUID().toString();
        return s.substring(0, 8) + s.substring(9, 13) + s.substring(14, 18) + s.substring(19, 23) + s.substring(24);
    }

    public static void main(String[] args) {
        System.out.println(createApplyNo("10000000"));
    }
}

