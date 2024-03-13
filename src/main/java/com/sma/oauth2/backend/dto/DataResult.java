package com.sma.oauth2.backend.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


// что нужно возвращать из RS
@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class DataResult {

    private String data; // бизнес-данные пользователя

    // можно использовать любые поля, в зависимости от задачи


    // сюда не нужно добавлять данные всего профайла пользователя, чтобы не нагружать запрос - только минимальные данные
    // если нужно получить полные данные пользователя (профайл) - это можно сделать отдельным методом

}
