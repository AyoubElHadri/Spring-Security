package com.example.springsecurity.student;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class Student {

    private final Integer studentId;
    private final String studentName;

}
