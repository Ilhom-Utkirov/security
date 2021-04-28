package com.example.demo.student;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController{

       private static final List<Student> STUDENTS = Arrays.asList(
                new Student(1, "james a"),
                new Student(2, "james b"),
                new Student(3, "james c")

       );

       // hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')
       @GetMapping
       @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
       public List<Student> getAllStudents(){
           System.out.println("getAllStudents");
           return STUDENTS;
       }

       @PostMapping
       @PreAuthorize("hasAuthority('student:write')")
       public void registerNewStudent(@RequestBody Student student){
           System.out.println("register new student");
           System.out.println(student);
       }
        @DeleteMapping(path = "{studentId}")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public void deleteStudent(@PathVariable("studentId") Integer studentId){
            System.out.println("deleteStudent");
           System.out.println(studentId);
        }

        @PutMapping(path = "{studentId}")
        @PreAuthorize("hasRole('ROLE_ADMIN')")
        public  void updateStudent(@PathVariable("studentId") Integer studentId,@RequestBody  Student student){
            System.out.println("updateStudent");
           System.out.println(String.format("%s %s", studentId, student));
        }
}
