fn main() {
    #[cfg(windows)]
    {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("band.ico");
        resource.set("ProductName", "Anyinstaller Packager");
        resource.set("FileDescription", "Anyinstaller Packager");
        resource
            .compile()
            .expect("failed to embed Windows resources");
    }
}
