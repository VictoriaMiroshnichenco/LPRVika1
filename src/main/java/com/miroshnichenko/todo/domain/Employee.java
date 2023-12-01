package com.miroshnichenko.todo.domain;

import lombok.Data;
import org.springframework.data.annotation.Id;

//import org.springframework.data.relational.core.mapping.Table;

import javax.persistence.*;
//import jakarta.persistence.*;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;

import java.util.UUID;

@Data
@Entity
//@Table(name = "employee" )
public class Employee {

    @NotNull
    @Id
    @javax.persistence.Id

    private String id;
    @NotNull
    @NotBlank
    private String name;
    private String about;
//    @MappedCollection(idColumn = "ownerid")
    //private Set<ToDo> tasks = new HashSet<>();


    private LocalDateTime created;
    private LocalDateTime modified;
    private boolean active;
//    @OneToMany(fetch = FetchType.LAZY)
//@JoinColumn(name = "employee", referencedColumnName = "id")
//    private Set<ToDo> tasks;

    //possibly will use for create form
    public Employee(){
        LocalDateTime date = LocalDateTime.now();
        this.id = UUID.randomUUID().toString();
        this.created = date;
        this.modified = date;
    }

    public Employee(String name){
        this();
        this.name = name;
    }

}
