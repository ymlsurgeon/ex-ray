# Wysimark-lite

A modern and clean rich text editor for React, supporting CommonMark and GFM Markdown spec.

wysimark ( https://github.com/portive/wysimark ) is a modern and clean rich text editor for React, supporting CommonMark and GFM Markdown spec. It is a fork of wysimark with some modifications to make it more lightweight and easier to use.

Thanks to the original author of wysimark, portive m(_ _)m

[日本語版 README はこちら](README_ja.md)

## Demo

You can try out the editor using storybook in the following link:
https://takeshy.github.io/wysimark-lite

## Usage

### As React Component

```bash
npm install wysimark-lite
```

```tsx
import { Editable, useEditor } from "wysimark-lite";
import React from "react";

const Editor: React.FC = () => {
  const [value, setValue] = React.useState("");
  const editor = useEditor({});

  return (
    <div style={{ width: "800px" }}>
      <Editable editor={editor} value={value} onChange={setValue} />
    </div>
  );
};
```

### Editor Options

The `useEditor` hook accepts the following options:

```tsx
const editor = useEditor({
  // Enable raw markdown editing mode (default: true = disabled)
  disableRawMode: false,

  // Enable highlight mark feature (default: true = disabled)
  disableHighlight: false,

  // Disable task list / checklist (default: false)
  disableTaskList: true,

  // Disable code block (default: false)
  disableCodeBlock: true,
});
```

| Option | Default | Description |
|--------|---------|-------------|
| `disableRawMode` | `true` | When `false`, shows a toggle button to switch between WYSIWYG and raw Markdown editing |
| `disableHighlight` | `true` | When `false`, shows a highlight button in the toolbar. Highlight is saved as `<mark>text</mark>` in Markdown |
| `disableTaskList` | `false` | When `true`, hides the task list (checklist) button from the toolbar |
| `disableCodeBlock` | `false` | When `true`, hides the code block button from the toolbar |

### With Image Upload

You can enable image file upload by providing the `onImageChange` callback:

```tsx
import { Editable, useEditor } from "wysimark-lite";
import React from "react";

const Editor: React.FC = () => {
  const [value, setValue] = React.useState("");
  const editor = useEditor({});

  const handleImageUpload = async (file: File): Promise<string> => {
    // Upload file to your server and return the URL
    const formData = new FormData();
    formData.append("image", file);
    const response = await fetch("/api/upload", { method: "POST", body: formData });
    const { url } = await response.json();
    return url;
  };

  return (
    <div style={{ width: "800px" }}>
      <Editable
        editor={editor}
        value={value}
        onChange={setValue}
        onImageChange={handleImageUpload}
      />
    </div>
  );
};
```

When `onImageChange` is provided:
- The image dialog shows a radio button to switch between URL input and file upload
- **Drag and drop** image files directly into the editor to insert them at the cursor position

### Direct Initialization

You can also initialize the editor directly on an HTML element:

# you use rails importmap, add the following line to your importmap.rb
※ @latest is the latest version of wysimark-lite. If you want to specify a version, replace @latest with the version you want to use.
```
pin "wysimark-lite", to: "https://cdn.jsdelivr.net/npm/wysimark-lite@latest/dist/index.js"
```

```html
<div id="editor"></div>
<script type="module">
  import { createWysimark } from "wysimark-lite";

  const editor = createWysimark(document.getElementById("editor"), {
    initialMarkdown: "# Hello Wysimark\n\nStart typing here...",
    onChange: (markdown) => {
      console.log("Markdown changed:", markdown);
    },
  });
</script>
```

## Features

- **Modern Design**: Clean and contemporary interface that integrates seamlessly with React applications
- **Raw Markdown Mode**: Switch between WYSIWYG and raw Markdown editing modes (enable with `disableRawMode: false`)
- **Highlight Support**: Highlight text with `<mark>` tags (enable with `disableHighlight: false`)
- **Image Upload Support**: Upload images via file picker or drag and drop when `onImageChange` callback is provided
- **Code Block with Custom Language**: Click on the language label to enter any language name
- **User-Friendly Interface**:
  - Simplified toolbar with toggle buttons (click to activate/deactivate formatting)
  - Markdown shortcuts (e.g., `**` for **bold**, `#` for heading)
  - Keyboard shortcuts (e.g., `Ctrl/Cmd + B` for bold)
  - Japanese localized UI (toolbar and menu items in Japanese)
- **Enhanced Link Editing**:
  - Edit link text and tooltip directly in the link dialog
  - Both insert and edit dialogs support text and tooltip fields
- **Enhanced List Support**:
  - Nested lists support (create hierarchical lists with multiple levels)
  - Mix different list types in the hierarchy
- **Enhanced Table Editing**:
  - Press `Enter` in a table cell to insert a line break (soft break)
  - Press `Shift+Enter` to move to the next cell
  - Press `Tab` in the last cell to exit the table and create a new paragraph
- **Smart Block Splitting**: When applying heading/paragraph styles to multi-line blocks, only the selected lines are converted
- **Cursor Position Preservation**: Cursor position is maintained after element type conversion (e.g., paragraph to heading)

## Browser Support

- Google Chrome
- Apple Safari
- Microsoft Edge
- Firefox

## Requirements

- React >= 17.x
- React DOM >= 17.x

## License

MIT
