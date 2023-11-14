package org.bcdns.credential.utils;

import org.bcdns.credential.common.utils.RedisUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class DistributedLock {
    @Autowired
    private RedisUtil redisUtil;
    private int lockTimeout = 5000; // ms

    /**
     * get lock
     * @param lockKey
     * @param identifier
     * @return
     */
    public boolean acquireLock(String lockKey,String identifier) {
        long startTime = System.currentTimeMillis();
        try {
            while (System.currentTimeMillis() - startTime < lockTimeout) {
                if (redisUtil.setnx(lockKey, identifier) == 1) {
                    redisUtil.pexpire(lockKey, lockTimeout);
                    return true;
                }
                Thread.sleep(100);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    /**
     * release lock
     * @param lockKey
     * @param identifier
     */
    public void releaseLock(String lockKey,String identifier) {
        if (redisUtil.get(lockKey).equals(identifier)) {
            redisUtil.del(lockKey);
        }
    }

}
