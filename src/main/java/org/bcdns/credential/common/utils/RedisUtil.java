package org.bcdns.credential.common.utils;

import com.alibaba.druid.filter.config.ConfigTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import javax.annotation.PostConstruct;

@Component
public class RedisUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(RedisUtil.class);

    private static JedisPool pool = null;


    @Value("${redis.host}")
    public String ip;
    @Value("${redis.port}")
    public int port;
    @Value("${redis.password}")
    public String encryptPassword;
    @Value("${redis.publicKey}")
    public String publicKey;


    @PostConstruct
    public void setPool() {
        try {
            if (pool == null) {
                String password = ConfigTools.decrypt(publicKey, encryptPassword);
                JedisPoolConfig config = new JedisPoolConfig();
                config.setMaxTotal(10000);
                config.setMaxIdle(2000);
                config.setMaxWaitMillis(1000 * 100);
                config.setTestOnBorrow(true);
                pool = new JedisPool(config, ip, port, 100000, password);
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    public String get(String key) {
        Jedis jedis = null;
        String value = null;
        try {
            jedis = pool.getResource();
            value = jedis.get(key);
        } catch (Exception e) {
            LOGGER.info(e.getMessage(), e);
        } finally {
            returnResource(pool, jedis);
        }
        return value;
    }

    public Long del(String... keys) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.del(keys);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
    }

    public Long setnx(String key, String value) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.setnx(key, value);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
    }

    public Long pexpire(String key, long time) {
        Jedis jedis = null;
        try {
            jedis = pool.getResource();
            return jedis.pexpire(key, time);
        } catch (Exception e) {
            LOGGER.error(e.getMessage());
            return 0L;
        } finally {
            returnResource(pool, jedis);
        }
    }

    public String setex(String key, String value, int seconds) {
        Jedis jedis = null;
        String res = null;
        try {
            jedis = pool.getResource();
            res = jedis.setex(key, seconds, value);
        } catch (Exception e) {

            LOGGER.error(e.getMessage());
        } finally {
            returnResource(pool, jedis);
        }
        return res;
    }

    public static void returnResource(JedisPool pool, Jedis jedis) {
        if (jedis != null) {
            pool.returnResource(jedis);
        }
    }
}