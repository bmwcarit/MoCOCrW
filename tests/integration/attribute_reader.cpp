#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pkcs11.h>
#include <dlfcn.h>

int main() {
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_ULONG ulSlotCount;

    // Load the PKCS#11 library
    void *libHandle = dlopen("/usr/lib/softhsm/libsofthsm2.so", RTLD_LAZY);
    if (libHandle == NULL) {
        printf("Failed to load PKCS#11 library.\n");
        return 1;
    }

    // Get the function list
    CK_C_GetFunctionList pGetFunctionList = (CK_C_GetFunctionList)dlsym(libHandle, "C_GetFunctionList");
    if (pGetFunctionList == NULL) {
        printf("Failed to get function list.\n");
        dlclose(libHandle);
        return 1;
    }

    // Initialize the function list
    rv = pGetFunctionList(&pFunctionList);
    if (rv != CKR_OK) {
        printf("Failed to initialize function list. Error: %lu\n", rv);
        dlclose(libHandle);
        return 1;
    }

    // Initialize PKCS#11
    rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK) {
        printf("Failed to initialize PKCS#11. Error: %lu\n", rv);
        dlclose(libHandle);
        return 1;
    }

    // Get the list of available slots
    rv = pFunctionList->C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to get slot count.\n");
        pFunctionList->C_Finalize(NULL);
        return 1;
    }

    if (ulSlotCount == 0) {
        fprintf(stderr, "No slots available.\n");
        pFunctionList->C_Finalize(NULL);
        return 1;
    }

    pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    rv = pFunctionList->C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to get slot list.\n");
        pFunctionList->C_Finalize(NULL);
        free(pSlotList);
        return 1;
    }

    for (int slot = 0; slot < ulSlotCount; ++slot) {

        // Open a session
        rv = pFunctionList->C_OpenSession(
                pSlotList[slot], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to open a session.\n");
            pFunctionList->C_Finalize(NULL);
            free(pSlotList);
            return 1;
        }

        // Login to the session (you may need to modify this for your specific HSM)
        CK_UTF8CHAR pin[] = "1234";
        rv = pFunctionList->C_Login(session, CKU_USER, pin, sizeof(pin) - 1);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to login.\n");
            pFunctionList->C_CloseSession(session);
            pFunctionList->C_Finalize(NULL);
            free(pSlotList);
            return 1;
        }

        // List objects
        CK_OBJECT_HANDLE objHandle;
        CK_ULONG objCount;

        rv = pFunctionList->C_FindObjectsInit(session, NULL_PTR, 0);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to initialize object search.\n");
            pFunctionList->C_CloseSession(session);
            pFunctionList->C_Finalize(NULL);
            free(pSlotList);
            return 1;
        }

        rv = pFunctionList->C_FindObjects(session, &objHandle, 1, &objCount);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to find objects.\n");
            pFunctionList->C_FindObjectsFinal(session);
            pFunctionList->C_CloseSession(session);
            pFunctionList->C_Finalize(NULL);
            free(pSlotList);
            return 1;
        }

        //printf("Found %lu object(s):\n", objCount);

        //for (CK_ULONG i = 0; i < objCount; i++) {
        int i= 0;
        while(objCount != 0){
            //printf("innerloop: %d\n", i);
            CK_ATTRIBUTE objTemplate[] = {{CKA_LABEL, NULL_PTR, 32},
                                          {CKA_CLASS, NULL_PTR, 32},
                                          {CKA_KEY_TYPE, NULL_PTR, 32},
                                          {CKA_EXTRACTABLE, NULL_PTR, 1},
                                          {CKA_SENSITIVE, NULL_PTR, 1}
            };

            /*CK_ATTRIBUTE objTemplate[] = {{CKA_LABEL, NULL_PTR, 32},
                                          {CKA_EXTRACTABLE, NULL_PTR, 1},
                                          {CKA_SENSITIVE, NULL_PTR, 1}};*/

            /*objTemplate[0].pValue = NULL;
            objTemplate[1].pValue = NULL;
            objTemplate[2].pValue = NULL;
            objTemplate[3].pValue = NULL;
            objTemplate[4].pValue = NULL;

            rv = pFunctionList->C_GetAttributeValue(session, objHandle, objTemplate, 5);
            if (rv != CKR_OK) {
                fprintf(stderr, "Failed to get object attributes.\n");
                break;
            }*/

            // Allocate memory for attribute values
            objTemplate[0].pValue = (CK_BYTE_PTR)calloc(objTemplate[0].ulValueLen, 1);
            objTemplate[1].pValue = (CK_BYTE_PTR)malloc(objTemplate[1].ulValueLen);
            objTemplate[2].pValue = (CK_BYTE_PTR)malloc(objTemplate[2].ulValueLen);
            objTemplate[3].pValue = (CK_BYTE_PTR)malloc(objTemplate[3].ulValueLen);
            objTemplate[4].pValue = (CK_BYTE_PTR)malloc(objTemplate[4].ulValueLen);

            rv = pFunctionList->C_GetAttributeValue(session, objHandle, objTemplate, 5);
            if (rv != CKR_OK) {
                //fprintf(stderr, "Object %d: Failed to get object attributes -> %s.\n", i+1, (char *)objTemplate[0].pValue);
                //break;
            } else {
                //printf("pSlotList5 %p:\n", pSlotList);

                if(strlen((char *)objTemplate[0].pValue) == 0) {
                    sprintf((char *)objTemplate[0].pValue, "emptylabel");
                }

                printf("%s SENSITIVE:%d EXTRACTABLE:%d\n", (char *)objTemplate[0].pValue, *(unsigned char*) objTemplate[4].pValue, *(unsigned char*) objTemplate[3].pValue);

                /*printf("Object %lu:\n", i + 1);
                printf("  Label: %s\n", (char *)objTemplate[0].pValue);
                printf("  Class: %lu\n", *(CK_OBJECT_CLASS *)objTemplate[1].pValue);
                printf("  Key Type: %lu\n", *(CK_KEY_TYPE *)objTemplate[2].pValue);
                printf("  EXTRACTABLE: %d\n", *(unsigned char*) objTemplate[3].pValue);
                printf("  SENSITIVE: %d\n", *(unsigned char*) objTemplate[4].pValue);*/
            }
            // Free allocated memory
            free(objTemplate[0].pValue);
            free(objTemplate[1].pValue);
            free(objTemplate[2].pValue);
            free(objTemplate[3].pValue);
            free(objTemplate[4].pValue);


            // Move to the next object
            rv = pFunctionList->C_FindObjects(session, &objHandle, 1, &objCount);
            if (rv != CKR_OK) {
                //printf("innerloop exit2\n");
                fprintf(stderr, "Failed to find objects.\n");
                break;
            }
            i = i + 1;
        }

        //printf("innerloop end\n");

        pFunctionList->C_FindObjectsFinal(session);

        rv = pFunctionList->C_Logout(session);
        if (rv != CKR_OK) {
            fprintf(stderr, "Failed to logout.\n");
        }
        pFunctionList->C_CloseSession(session);
    }

    /*rv = pFunctionList->C_Logout(session);
    if (rv != CKR_OK) {
        fprintf(stderr, "Failed to logout.\n");
    }

    pFunctionList->C_FindObjectsFinal(session);
    pFunctionList->C_CloseSession(session);*/
    pFunctionList->C_Finalize(NULL);
    free(pSlotList);

    return 0;
}