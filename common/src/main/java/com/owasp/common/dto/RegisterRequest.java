package com.owasp.common.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 註冊請求 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {
    
    @NotBlank(message = "帳號不可為空")
    @Size(min = 4, max = 20, message = "帳號長度需為 4-20 字元")
    private String username;
    
    @NotBlank(message = "密碼不可為空")
    @Size(min = 6, message = "密碼長度至少 6 字元")
    private String password;
    
    @NotBlank(message = "電子郵件不可為空")
    @Email(message = "請輸入有效的電子郵件")
    private String email;
    
    private String fullName;
}
