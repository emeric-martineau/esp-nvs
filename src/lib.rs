use std::ffi::{c_char, c_int, c_void, CString};

use esp_idf_sys::{
    nvs_close, nvs_commit, nvs_erase_key, nvs_flash_init_partition, nvs_get_blob, nvs_get_i16,
    nvs_get_i32, nvs_get_i64, nvs_get_i8, nvs_get_str, nvs_get_u16, nvs_get_u32, nvs_get_u64,
    nvs_get_u8, nvs_handle_t, nvs_open, nvs_open_from_partition, nvs_open_mode_t_NVS_READONLY,
    nvs_open_mode_t_NVS_READWRITE, nvs_set_blob, nvs_set_i16, nvs_set_i32, nvs_set_i64, nvs_set_i8,
    nvs_set_str, nvs_set_u16, nvs_set_u32, nvs_set_u64, nvs_set_u8, ESP_ERR_NVS_BASE,
    ESP_ERR_NVS_CONTENT_DIFFERS, ESP_ERR_NVS_CORRUPT_KEY_PART, ESP_ERR_NVS_ENCR_NOT_SUPPORTED,
    ESP_ERR_NVS_INVALID_HANDLE, ESP_ERR_NVS_INVALID_LENGTH, ESP_ERR_NVS_INVALID_NAME,
    ESP_ERR_NVS_INVALID_STATE, ESP_ERR_NVS_KEYS_NOT_INITIALIZED, ESP_ERR_NVS_KEY_TOO_LONG,
    ESP_ERR_NVS_NEW_VERSION_FOUND, ESP_ERR_NVS_NOT_ENOUGH_SPACE, ESP_ERR_NVS_NOT_FOUND,
    ESP_ERR_NVS_NOT_INITIALIZED, ESP_ERR_NVS_NO_FREE_PAGES, ESP_ERR_NVS_PAGE_FULL,
    ESP_ERR_NVS_PART_NOT_FOUND, ESP_ERR_NVS_READ_ONLY, ESP_ERR_NVS_REMOVE_FAILED,
    ESP_ERR_NVS_TYPE_MISMATCH, ESP_ERR_NVS_VALUE_TOO_LONG, ESP_ERR_NVS_WRONG_ENCRYPTION,
    ESP_ERR_NVS_XTS_CFG_FAILED, ESP_ERR_NVS_XTS_CFG_NOT_FOUND, ESP_ERR_NVS_XTS_DECR_FAILED,
    ESP_ERR_NVS_XTS_ENCR_FAILED,
};

/// NVS error return by ESP-IDF
pub enum NvsError {
    // Initialization errors
    NotInitialized,

    // Resource-related errors
    NotFound,
    PartitionNotFound,
    KeysNotInitialized,

    // Space constraints
    NotEnoughSpace,
    PageFull,
    ValueTooLong,
    KeyTooLong,

    // Type and validation errors
    TypeMismatch,
    InvalidName,
    InvalidHandle,
    InvalidLength,
    NoFreeSpace,
    WrongEncryption,

    // State management
    Readonly,
    InvalidState,
    ContentDiffers,

    // Operation failures
    RemoveFailed,
    CorruptKeyPartition,
    NewVersionFound,

    // Encryption-specific errors
    EncryptionFailed,
    DecryptionFailed,
    EncryptionNotSupported,

    // Configuration errors
    ConfigFailed,
    ConfigNotFound,

    Other(i32),
    Unknown,
}

impl From<i32> for NvsError {
    /// Convert integer value return by ESP-IDF to a Rust enum
    fn from(error_code: i32) -> Self {
        match error_code {
            e if e >= ESP_ERR_NVS_BASE => match e {
                ESP_ERR_NVS_NOT_INITIALIZED => NvsError::NotInitialized,
                ESP_ERR_NVS_NOT_FOUND => NvsError::NotFound,
                ESP_ERR_NVS_TYPE_MISMATCH => NvsError::TypeMismatch,
                ESP_ERR_NVS_READ_ONLY => NvsError::Readonly,
                ESP_ERR_NVS_NOT_ENOUGH_SPACE => NvsError::NotEnoughSpace,
                ESP_ERR_NVS_INVALID_NAME => NvsError::InvalidName,
                ESP_ERR_NVS_INVALID_HANDLE => NvsError::InvalidHandle,
                ESP_ERR_NVS_REMOVE_FAILED => NvsError::RemoveFailed,
                ESP_ERR_NVS_KEY_TOO_LONG => NvsError::KeyTooLong,
                ESP_ERR_NVS_PAGE_FULL => NvsError::PageFull,
                ESP_ERR_NVS_INVALID_STATE => NvsError::InvalidState,
                ESP_ERR_NVS_INVALID_LENGTH => NvsError::InvalidLength,
                ESP_ERR_NVS_NO_FREE_PAGES => NvsError::NoFreeSpace,
                ESP_ERR_NVS_VALUE_TOO_LONG => NvsError::ValueTooLong,
                ESP_ERR_NVS_PART_NOT_FOUND => NvsError::PartitionNotFound,
                ESP_ERR_NVS_NEW_VERSION_FOUND => NvsError::NewVersionFound,
                ESP_ERR_NVS_XTS_ENCR_FAILED => NvsError::EncryptionFailed,
                ESP_ERR_NVS_XTS_DECR_FAILED => NvsError::DecryptionFailed,
                ESP_ERR_NVS_XTS_CFG_FAILED => NvsError::ConfigFailed,
                ESP_ERR_NVS_XTS_CFG_NOT_FOUND => NvsError::ConfigNotFound,
                ESP_ERR_NVS_ENCR_NOT_SUPPORTED => NvsError::EncryptionNotSupported,
                ESP_ERR_NVS_KEYS_NOT_INITIALIZED => NvsError::KeysNotInitialized,
                ESP_ERR_NVS_CORRUPT_KEY_PART => NvsError::CorruptKeyPartition,
                ESP_ERR_NVS_WRONG_ENCRYPTION => NvsError::WrongEncryption,
                ESP_ERR_NVS_CONTENT_DIFFERS => NvsError::ContentDiffers,
                e => NvsError::Other(e),
            },
            _ => NvsError::Unknown,
        }
    }
}

/// Check if error or return ().
fn err(error: i32) -> Result<(), NvsError> {
    if error != 0 {
        return Err(NvsError::from(error));
    }

    Ok(())
}

/// Internal usage to build
pub struct EspNvsBuilder {
    /// Name of preference
    name: String,
    /// Is preference is in read-only mode
    is_readonly: bool,
    /// Partition
    partition_label: Option<String>,
}

impl EspNvsBuilder {
    /// Return default builder
    pub fn default(name: String) -> Self {
        Self {
            name,
            is_readonly: false,
            partition_label: None,
        }
    }

    /// Return a builder for readonly NVS builder
    pub fn readonly(name: String) -> Self {
        Self {
            name,
            is_readonly: true,
            partition_label: None,
        }
    }

    /// Build Preference object
    pub fn build(&self) -> Result<EspNvs, NvsError> {
        // Create struct at first to use pointer of this object
        let c_name = CString::new(self.name.clone()).unwrap();
        let c_name_ptr: *const c_char = c_name.as_ptr() as *const c_char;
        // Flags for memory
        let open_mode = if self.is_readonly {
            nvs_open_mode_t_NVS_READONLY
        } else {
            nvs_open_mode_t_NVS_READWRITE
        };

        let mut pref = EspNvs {
            c_name,
            is_readonly: self.is_readonly,
            c_partition_label: None,
            handle: 0,
        };

        // In case of no partition label
        if self.partition_label.is_none() {
            err(unsafe { nvs_open(c_name_ptr, open_mode, &mut pref.handle) })?;

            return Ok(pref);
        }

        // In case with partition label
        let c_partition_label = CString::new(self.partition_label.clone().unwrap()).unwrap();
        let c_partition_label_ptr: *const c_char = c_partition_label.as_ptr() as *const c_char;

        pref.c_partition_label = Some(c_partition_label);

        err(unsafe { nvs_flash_init_partition(c_partition_label_ptr) })?;

        err(unsafe {
            nvs_open_from_partition(
                c_partition_label_ptr,
                c_name_ptr,
                open_mode,
                &mut pref.handle,
            )
        })?;

        Ok(pref)
    }
}

/// Peferences
pub struct EspNvs {
    /// Name of preference
    c_name: CString,
    /// Is preference is in read-only mode
    is_readonly: bool,
    /// Partition
    c_partition_label: Option<CString>,
    /// Internal handle of nvs
    handle: nvs_handle_t,
}

/// Auto-drop support
impl Drop for EspNvs {
    fn drop(&mut self) {
        self.close()
    }
}

impl EspNvs {
    /// Is preference is in read-only mode
    pub fn is_readonly(&self) -> bool {
        self.is_readonly
    }

    /// Name
    pub fn name(&self) -> String {
        self.c_name.clone().into_string().unwrap()
    }

    /// Partition name
    pub fn partition_label(&self) -> Option<String> {
        if let Some(p) = self.c_partition_label.as_ref() {
            return Some(p.clone().into_string().unwrap());
        }

        None
    }

    /// Close the storage handle and free any allocated resources.
    pub fn close(&self) {
        unsafe {
            nvs_close(self.handle);
        }
    }

    /// Erase key-value pair with given key name.
    /// See Erase key-value pair with given key name.
    pub fn remove(&self, key: &str) -> Result<(), NvsError> {
        let c_key = CString::new(key).unwrap();
        let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

        unsafe {
            err(nvs_erase_key(self.handle, c_key_ptr))?;

            err(nvs_commit(self.handle))?;
        }

        Ok(())
    }

    /// Store en string.
    pub fn write_blob(&self, key: &str, value: &[u8]) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            let c_value_ptr: *const c_void = value.as_ptr() as *const c_void;

            err(nvs_set_blob(
                self.handle,
                c_key_ptr,
                c_value_ptr,
                value.len(),
            ))?;
        }

        Ok(())
    }

    /// Read en string.
    pub fn read_blob(&self, key: &str) -> Result<Vec<i8>, NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            let mut required_size: usize = 0;
            let mut null_pointer: c_int = 0;
            let p_null_pointer = &mut null_pointer as *mut c_int as *mut c_void;

            // First get size of data
            err(nvs_get_blob(
                self.handle,
                c_key_ptr,
                p_null_pointer,
                &mut required_size,
            ))?;

            // Reserve memory space
            let mut data = vec![0i8; required_size + 1];
            let data_ptr = data.as_mut_ptr() as *mut c_void;

            err(nvs_get_blob(
                self.handle,
                c_key_ptr,
                data_ptr,
                &mut required_size,
            ))?;

            Ok(data)
        }
    }

    /// Store en string.
    pub fn write_str(&self, key: &str, value: &str) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            let c_value = CString::new(value).unwrap();
            let c_value_ptr: *const c_char = c_value.as_ptr() as *const c_char;

            err(nvs_set_str(self.handle, c_key_ptr, c_value_ptr))?;
        }

        Ok(())
    }

    /// Read en string.
    pub fn read_str(&self, key: &str) -> Result<String, NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            let mut required_size: usize = 0;
            let mut null_pointer: c_int = 0;
            let p_null_pointer = &mut null_pointer as *mut c_int as *mut i8;

            // First get size of data
            err(nvs_get_str(
                self.handle,
                c_key_ptr,
                p_null_pointer,
                &mut required_size,
            ))?;

            // Reserve memory space
            let mut data = vec![0; required_size + 1];
            let data_ptr = data.as_mut_ptr() as *mut c_char;

            err(nvs_get_str(
                self.handle,
                c_key_ptr,
                data_ptr,
                &mut required_size,
            ))?;

            let cstr = CString::from_vec_with_nul(data);

            if cstr.is_err() {
                return Err(NvsError::Unknown);
            }

            let converted_str = cstr.unwrap().into_string();

            if converted_str.is_err() {
                return Err(NvsError::Unknown);
            }

            Ok(converted_str.unwrap())
        }
    }

    /// Store a i8 value.
    pub fn write_i8(&self, key: &str, value: i8) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_i8(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a i8 value.
    pub fn read_i8(&self, key: &str) -> Result<i8, NvsError> {
        let mut value: i8 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_i8(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }

    /// Store a u8 value.
    pub fn write_u8(&self, key: &str, value: u8) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_u8(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a u8 value.
    pub fn read_u8(&self, key: &str) -> Result<u8, NvsError> {
        let mut value: u8 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_u8(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }

    /// Store a i16 value.
    pub fn write_i16(&self, key: &str, value: i16) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_i16(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a i16 value.
    pub fn read_i16(&self, key: &str) -> Result<i16, NvsError> {
        let mut value: i16 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_i16(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }

    /// Store a u16 value.
    pub fn write_u16(&self, key: &str, value: u16) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_u16(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a u16 value.
    pub fn read_u16(&self, key: &str) -> Result<u16, NvsError> {
        let mut value: u16 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_u16(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }

    /// Store a i32 value.
    pub fn write_i32(&self, key: &str, value: i32) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_i32(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a i32 value.
    pub fn read_i32(&self, key: &str) -> Result<i32, NvsError> {
        let mut value: i32 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_i32(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }

    /// Store a u32 value.
    pub fn write_u32(&self, key: &str, value: u32) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_u32(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a u32 value.
    pub fn read_u32(&self, key: &str) -> Result<u32, NvsError> {
        let mut value: u32 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_u32(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }

    /// Store a i64 value.
    pub fn write_i64(&self, key: &str, value: i64) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_i64(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a i64 value.
    pub fn read_i64(&self, key: &str) -> Result<i64, NvsError> {
        let mut value: i64 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_i64(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }

    /// Store a u64 value.
    pub fn write_u64(&self, key: &str, value: u64) -> Result<(), NvsError> {
        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_set_u64(self.handle, c_key_ptr, value))?;
        }

        Ok(())
    }

    /// Get a u64 value.
    pub fn read_u64(&self, key: &str) -> Result<u64, NvsError> {
        let mut value: u64 = 0;

        unsafe {
            let c_key = CString::new(key).unwrap();
            let c_key_ptr: *const c_char = c_key.as_ptr() as *const c_char;

            err(nvs_get_u64(self.handle, c_key_ptr, &mut value))?;
        }

        Ok(value)
    }
}
