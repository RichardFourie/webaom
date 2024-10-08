// Copyright (C) 2005-2006 epoximator
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

/*
 * Created on 18.des.2005 12:36:32
 * Filename: UserPass.java
 */
package epox.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import com.bitzi.util.Base32;

public class UserPass {
    public String usr, psw, key;

    public UserPass(String u, String p, String k) {
        usr = u;
        psw = p;
        key = k;
    }

    public void set(String s) {
        try {
            String a[] = U.split(s, ':');
            usr = a[0];
            psw = UserPass.dec(a[1]);
            key = UserPass.dec(a[2]);
        } catch (@SuppressWarnings("unused") Exception e) {
            //
        }
    }

    public String get(boolean sp) {
        if (!sp) {
            return usr;
        }

        return usr + ":" + UserPass.nne(psw) + ":" + UserPass.nne(key);
    }

    private static String nne(String s) {
        if (s == null || s.length() < 1) {
            return "";
        }

        return UserPass.enc(s);
    }

    private static byte[] envk() throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(System.getProperty("os.name", "").getBytes());
        md.update(System.getProperty("os.version", "").getBytes());
        md.update(System.getProperty("os.arch", "").getBytes());
        md.update(System.getProperty("user.name", "").getBytes());
        md.update(System.getProperty("user.home", "").getBytes());
        md.update(System.getProperty("user.language", "").getBytes());
        return md.digest();
    }

    private static String enc(String p) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(UserPass.envk(), "AES"));
            return Base32.encode(c.doFinal(p.getBytes()));
        } catch (@SuppressWarnings("unused") Exception e) {
            return null;
        }
    }

    private static String dec(String p) {
        try {
            Cipher c = Cipher.getInstance("AES");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(UserPass.envk(), "AES"));
            return new String(c.doFinal(Base32.decode(p)));
        } catch (@SuppressWarnings("unused") Exception e) {
            return null;
        }
    }
}
