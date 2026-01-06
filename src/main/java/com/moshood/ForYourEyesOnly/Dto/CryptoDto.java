package com.moshood.ForYourEyesOnly.Dto;

import org.springframework.web.multipart.MultipartFile;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Data
public class CryptoDto {
	
	private  MultipartFile file;
	private  int key;
	
}
