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
 * Created on 24.10.05
 *
 * @version 	01 (1.14)
 * @author 		epoximator
 */

package epox.webaom;

public class JobCnt {
    private int mItot = 0;
    private final int mIcnt[] = new int[JobCnt.I_LEN];

    public synchronized int getProgress() {
        int div = mItot - mIcnt[JobCnt.I_HLT] - mIcnt[JobCnt.I_ERR];

        if (div == 0) {
            return 0;
        }
        return 1000 * (mIcnt[JobCnt.I_FIN]) / div;
    }

    public synchronized String getStatus() {
        StringBuilder s = new StringBuilder();

        for (int i = 0; i < JobCnt.I_LEN; i++) {
            s.append(JobCnt.S_NAM[i]).append("=").append(mIcnt[i]).append(" ");
        }
        return s.append(" tot=").append(mItot).toString();
    }

    public synchronized void register(int os, int oh, int ns, int nh) {
        edit(os, oh, false);
        edit(ns, nh, true);
    }

    private void edit(int status, int health, boolean inc) {

        if (status < 0) {
            mItot++;
            return;
        }
        int type = JobCnt.I_HLT;

        if (A.bitcmp(health, Job.H_NORMAL) && (A.bitcmp(status, Job.S_DO) || A.bitcmp(status, Job.S_DOING))) {

            if (A.bitcmp(status, Job.D_DIO)) {
                type = JobCnt.I_DIO;
            } else if (A.bitcmp(status, Job.D_NIO)) {
                type = JobCnt.I_NIO;
            }
        } else if (A.bitcmp(health, Job.H_NORMAL) && A.bitcmp(status, Job.FINISHED)) {
            type = JobCnt.I_FIN;
        } else if (A.bitcmp(status, Job.FAILED) || A.bitcmp(status, Job.UNKNOWN)) {
            type = JobCnt.I_ERR;
        }

        if (inc) {
            mIcnt[type]++;
        } else {
            mIcnt[type]--;
        }
    }

    public synchronized void reset() {

        for (int i = 0; i < JobCnt.I_LEN; i++) {
            mIcnt[i] = 0;
        }
        mItot = 0;
    }

    private static final int I_FIN = 0, I_DIO = 1, I_NIO = 2, I_ERR = 3, I_HLT = 4, I_LEN = 5;
    private static final String[] S_NAM = { "fin", "dio", "nio", "err", "hlt" };
}
