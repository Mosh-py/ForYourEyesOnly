package com.moshood.ForYourEyesOnly.model;

import org.springframework.web.multipart.MultipartFile;

public record AppResponse(byte[] file , String Message) {

}
