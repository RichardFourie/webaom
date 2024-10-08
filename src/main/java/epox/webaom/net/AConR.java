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
 * Created on 19.jan.2006 12:50:06
 * Filename: Reply.java
 */
package epox.webaom.net;

import java.net.SocketTimeoutException;

import epox.util.U;

public class AConR {
    public int code = -1;
    public String message = null;
    public String data = null, tag;

    public AConR(String sTag, int tag_len, String raw) throws AConEx, TagEx, SocketTimeoutException {
        String newRaw = raw;

        if (sTag != null && newRaw.length() > 0 && newRaw.charAt(0) == 't') {
            tag = newRaw.substring(0, tag_len + 1);

            if (!tag.equals(sTag)) {
                throw new TagEx();
            }
            newRaw = newRaw.substring(tag_len + 2);
        }

        try {
            code = Integer.parseInt(newRaw.substring(0, 3));
        } catch (@SuppressWarnings("unused") NumberFormatException e) {
            throw new AConEx(AConEx.ANIDB_SERVER_ERROR, "Unexpected response");
        }

        if ((code > 600 && code < 700) && code != 602) {
            throw new AConEx(AConEx.ANIDB_SERVER_ERROR, newRaw);
        }

        int i;

        switch (code) {
        case BANNED:
            i = newRaw.indexOf('\n');
            String why = "Unknown";
            if (i > 0) {
                why = newRaw.substring(i + 1);
            }
            throw new AConEx(AConEx.CLIENT_USER, "Banned: " + why);
        case LOGIN_ACCEPTED:
        case LOGIN_ACCEPTED_NEW_VER:
            i = newRaw.indexOf("LOGIN ACCEPTED");
            data = newRaw.substring(4, i - 1);
            message = newRaw.substring(i);
            break;
        case ENCRYPTION_ENABLED:
            i = newRaw.indexOf("ENCRYPTION ENABLED");
            data = newRaw.substring(4, i - 1);
            message = newRaw.substring(i);
            break;
        case ACCESS_DENIED:
            throw new AConEx(AConEx.CLIENT_USER);
        case SERVER_BUSY:
            throw new SocketTimeoutException();
        case CLIENT_BANNED:
            message = newRaw.substring(4, 17);
            // data = raw.substring(18);
            throw new AConEx(AConEx.CLIENT_BANNED);
        case CLIENT_VERSION_OUTDATED:
            throw new AConEx(AConEx.CLIENT_OUTDATED);
        case ILLEGAL_INPUT_OR_ACCESS_DENIED:
            throw new AConEx(AConEx.CLIENT_BUG, "Illegal Input or Access Denied");
        default:
            i = newRaw.indexOf('\n');
            if (i > 0) {
                message = newRaw.substring(4, i);
                data = newRaw.substring(i + 1);
            } else {
                message = newRaw.substring(4);
            }
        }
        data = U.htmldesc(data);
    }

    @Override
    public String toString() {
        return code + " " + message + " [" + data + "]";
    }

    ///////////////////////////////// REPLY CODES////////////////////////////////
    public static final int LOGIN_ACCEPTED = 200, // C
            LOGIN_ACCEPTED_NEW_VER = 201, // C
            LOGGED_OUT = 203, // C
//	STATS							=206, //N
//	TOP								=207, //N
//	UPTIME							=208, //N
            ENCRYPTION_ENABLED = 209, // N

            MYLIST_ENTRY_ADDED = 210, // C
            MYLIST_ENTRY_DELETED = 211, // C

            FILE = 220, // C
//	MYLIST							=221, //C
//	MYLIST_STATS					=222, //N

            ANIME = 230, // N
//	ANIME_BEST_MATCH				=231, //N
//	RANDOMANIME						=232, //N

            EPISODE = 240, // N
            GROUP = 250, // N

//	VOTED							=260, //N
//	VOTE_FOUND						=261, //N
//	VOTE_UPDATED					=262, //N
//	VOTE_REVOKED					=263, //N

            /*
             * NOTIFICATION_ENABLED =270, //C PUSHACK_CONFIRMED =280, //C
             * NOTIFYACK_SUCCESSFUL_M =281, //C NOTIFYACK_SUCCESSFUL_N =282, //C
             * NOTIFICATION =290, //C NOTIFYLIST =291, //C NOTIFYGET_MESSAGE =292, //C
             * NOTIFYGET_NOTIFY =293, //C SENDMSG_SUCCESSFUL =294, //C
             */
            /*
             * AFFIRMATIVE/NEGATIVE 3XX
             */
//	PONG							=300, //C
            API_PASSWORD_NOT_DEFINED = 309, FILE_ALREADY_IN_MYLIST = 310, // C
            MYLIST_ENTRY_EDITED = 311, // C
            NO_SUCH_FILE = 320, // C
            /*
             * NO_SUCH_ENTRY =321, //C MULTIPLE_FILES_FOUND =322, //N
             *
             * NO_SUCH_ANIME =330, //N NO_SUCH_EPISODE =340, //N NO_SUCH_GROUP =350, //N
             *
             * NO_SUCH_VOTE =360, //N INVALID_VOTE_TYPE =361, //N INVALID_VOTE_VALUE =362,
             * //N PERMVOTE_NOT_ALLOWED =363, //N ALREADY_PERMVOTED =364, //N
             *
             * NOTIFICATION_DISABLED =370, //C NO_SUCH_PACKET_PENDING =380, //C
             * NO_SUCH_ENTRY_M =381, //C NO_SUCH_ENTRY_N =382, //C
             *
             * NO_SUCH_MESSAGE =392, //C NO_SUCH_NOTIFY =393, //C
             */
            NO_SUCH_USER = 394, // C

//	NO_SUCH_DATA_ENTRY				=396, //N

            /*
             * NEGATIVE 4XX
             */

            NOT_LOGGED_IN = 403, // C
            NO_SUCH_MYLIST_FILE = 410, // C
            NO_SUCH_MYLIST_ENTRY = 411, // C

            /*
             * CLIENT SIDE FAILURE 5XX
             */

            LOGIN_FAILED = 500, // C
            LOGIN_FIRST = 501, // C
            ACCESS_DENIED = 502, // C
            CLIENT_VERSION_OUTDATED = 503, // C
            CLIENT_BANNED = 504, // C
            ILLEGAL_INPUT_OR_ACCESS_DENIED = 505, // C
            INVALID_SESSION = 506, // C
            ENCODING_NOT_SUPPORTED = 510, // M
            BANNED = 555, // C
//	UNKNOWN_COMMAND					=598, //C

            /*
             * SERVER SIDE FAILURE 6XX
             */

            INTERNAL_SERVER_ERROR = 600, // C
            SERVER_BUSY = 602;
//	ANIDB_OUT_OF_SERVICE			=601, //C
//	API_VIOLATION					=666; //C
}
