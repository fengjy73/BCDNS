package org.bcdns.credential.common.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.bcdns.credential.common.constant.Constants;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class JwtUtil {
    private static final String SECRET = "WQWRBIFhhhsda24b¥%7898R9iDSFDdsfdvcbnmii8Gvsgh#@C";
    private static Algorithm ALGORITHM;
    private static Map<String, Object> HEADER_CLAIMS = new HashMap<>();

    private static final String ISSUER = "BIF-CHAIN";

    static{
        HEADER_CLAIMS.put("typ", "JWT");
        HEADER_CLAIMS.put("alg", "HS256");
        try {
            ALGORITHM = Algorithm.HMAC256(SECRET);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String encode(Map<String, String> params){
        long expTime = TimeUnit.SECONDS.toMillis(Constants.ACCESS_TOKEN_EXPIRES);
        JWTCreator.Builder builder = JWT.create()
                .withHeader(HEADER_CLAIMS)
                .withIssuer(ISSUER)
                .withExpiresAt(new Date(System.currentTimeMillis() + expTime));

        if(params != null && params.size() > 0){
            params.forEach((k,v) -> {
                builder.withClaim(k, v);
            });
        }

        String token = builder.sign(ALGORITHM);

        return token;
    }

    public static Map<String, String> decode(String token){
        DecodedJWT jwt;
        try {
            JWTVerifier verifier = JWT.require(ALGORITHM)
                    .withIssuer(ISSUER)
                    .build(); //Reusable verifier instance
            jwt = verifier.verify(token);
            Map<String, Claim> claimsMap = jwt.getClaims();

            Map<String, String> resultMap = new HashMap<String, String>();
            if(!claimsMap.isEmpty()){
                claimsMap.forEach((k,v) -> {
                    if(!"iss".equals(k) && !"exp".equals(k)){
                        resultMap.put(k, v.asString());
                    }
                });
            }
            return resultMap;
        } catch (JWTVerificationException e) {
            e.printStackTrace();
            return null;
        }
    }
}
