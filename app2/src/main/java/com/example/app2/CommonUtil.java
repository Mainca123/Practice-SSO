package com.example.app2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CommonUtil {

    private CommonUtil() {

    }

    public static <T> String beanToString(T value) {
        if (value == null) {
            return null;
        } else {
            Class<?> clazz = value.getClass();
            if (clazz != Integer.TYPE && clazz != Integer.class) {
                if (clazz == String.class) {
                    return (String) value;
                } else if (clazz != Long.TYPE && clazz != Long.class) {
                    ObjectMapper mapper = new ObjectMapper();
                    mapper.registerModule(new JavaTimeModule());
                    mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
                    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                    mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
                    String jsonString = "";
                    try {
                        jsonString = mapper.writeValueAsString(value);
                    } catch (JsonProcessingException var5) {
                        log.error(var5.getMessage());
                        jsonString = "Can't build json from object";
                    }
                    return jsonString;
                } else {
                    return "" + value;
                }
            } else {
                return "" + value;
            }
        }
    }
}
