package com.securemessaging.dto;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public class UserSettingsDTO {
    @NotNull
    @Size(min = 1)
    private String settingsJson;

    public UserSettingsDTO() {
    }

    public UserSettingsDTO(String settingsJson) {
        this.settingsJson = settingsJson;
    }

    public String getSettingsJson() {
        return settingsJson;
    }

    public void setSettingsJson(String settingsJson) {
        this.settingsJson = settingsJson;
    }
}
