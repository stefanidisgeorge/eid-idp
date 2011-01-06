package be.fedict.eid.idp.spi;

import be.fedict.eid.applet.service.Identity;

public abstract class IdpUtil {

    public static String getGenderValue(Identity identity) {

        String genderValue;
        switch (identity.getGender()) {
            case MALE:
                genderValue = "1";
                break;
            case FEMALE:
                genderValue = "2";
                break;
            default:
                genderValue = "0";
                break;
        }
        return genderValue;
    }
}
