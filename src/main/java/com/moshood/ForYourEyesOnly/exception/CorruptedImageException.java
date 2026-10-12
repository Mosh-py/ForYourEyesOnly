package com.moshood.ForYourEyesOnly.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNPROCESSABLE_ENTITY)
public class CorruptedImageException extends RuntimeException {

    public CorruptedImageException(String message) {
        super(message);
    }

    public CorruptedImageException(String message, Throwable cause) {
        super(message, cause);
    }
}
