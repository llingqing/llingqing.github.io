/**
 * src/utils/code-copy-utils.ts
 * 代码复制工具（已移除冗余 else，修复 lint 报错）
 */

export function getCodeText(codeElement: Element): string {
	// 优先尝试按行提取（常见的 code 行结构）
	const lineSelectors = [
		".line", // 通用行类
		".code-line",
		".hljs-ln-line",
		".prism-line",
		".line-numbered .line",
	];
	const linesFound: string[] = [];

	for (const sel of lineSelectors) {
		const elems = codeElement.querySelectorAll<HTMLElement>(sel);
		if (elems.length > 0) {
			for (let i = 0; i < elems.length; i++) {
				linesFound.push(elems[i].textContent || "");
			}
			// 找到行结构后直接返回拼接结果
			if (linesFound.length > 0) return linesFound.join("\n");
		}
	}

	// 对于没有行结构的代码块，查找常见的 code 元素
	const codeElements = codeElement.querySelectorAll<HTMLElement>(".code:not(summary *)");
	if (codeElements.length > 0) {
		const elementLines: string[] = [];
		for (let i = 0; i < codeElements.length; i++) {
			const el = codeElements[i];
			elementLines.push(el.textContent || "");
		}
		return elementLines.join("\n");
	}

	// 回退到整个 code 元素的文本内容
	return codeElement.textContent || "";
}

/**
 * 处理连续空行，避免复制过多连续空行
 * 规则：将连续三个及以上换行压缩为适当数量（最少保留一个空行）
 */
export function processEmptyLines(code: string): string {
	return code.replace(/\n{3,}/g, (match) => {
		// match 是连续的换行符字符串，长度等于换行符数量
		const newlineCount = match.length;
		// 空行数为换行符数 - 1
		let emptyLineCount = newlineCount - 1;

		// 偶数空行：除以2；奇数空行： (空行数+1)/2 向下取整
		let resultEmptyLines: number;
		if (emptyLineCount % 2 === 0) {
			resultEmptyLines = emptyLineCount / 2;
		} else {
			resultEmptyLines = Math.floor((emptyLineCount + 1) / 2);
		}

		if (resultEmptyLines < 1) resultEmptyLines = 1;

		// 返回对应数量的换行符（再加一个换行符作为行尾）
		return "\n".repeat(resultEmptyLines + 1);
	});
}

/**
 * 复制文本到剪贴板，优先使用 Clipboard API，失败时回退到 execCommand 实现
 */
export async function copyToClipboard(text: string): Promise<boolean> {
	// 优先使用现代 Clipboard API
	if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.writeText) {
		try {
			await navigator.clipboard.writeText(text);
			return true;
		} catch (err) {
			// 继续尝试备用方案
			console.warn("Clipboard API 失败，尝试备用方案:", err);
		}
	}

	// 备用方案：创建 textarea，使用 document.execCommand("copy")
	if (typeof document === "undefined") {
		throw new Error("无法访问 document，不能执行复制操作");
	}

	const textArea = document.createElement("textarea");
	textArea.value = text;
	// 避免影响页面布局
	textArea.style.position = "fixed";
	textArea.style.left = "-99999px";
	textArea.style.top = "-99999px";
	textArea.setAttribute("aria-hidden", "true");
	document.body.appendChild(textArea);
	textArea.focus();
	textArea.select();

	try {
		const successful = document.execCommand("copy");
		if (!successful) {
			throw new Error("execCommand 返回 false");
		}
		return true;
	} catch (execErr) {
		console.error("execCommand 也失败了:", execErr);
		throw new Error("所有复制方法都失败了");
	} finally {
		document.body.removeChild(textArea);
	}
}

/**
 * 处理代码复制按钮点击事件
 * @param target 按钮元素或触发元素
 */
export async function handleCodeCopy(target: Element): Promise<void> {
	if (!target) return;

	// 寻找关联的代码容器：优先查找最近的 pre 或 code 元素
	let codeContainer: Element | null = null;

	// 如果按钮位于 code block 内，尝试向上查找 pre/code
	let el: Element | null = target as Element;
	while (el && !codeContainer) {
		if (el.tagName.toLowerCase() === "pre" || el.tagName.toLowerCase() === "code") {
			codeContainer = el;
			break;
		}
		el = el.parentElement;
	}

	// 如果没有直接在祖先链上找到，尝试根据常见 DOM 结构查找（例如按钮在 pre 的同级）
	if (!codeContainer) {
		const possiblePre = target.closest("pre");
		if (possiblePre) codeContainer = possiblePre;
	}

	// 如果仍未找到，则尝试在同级查找 code 元素
	if (!codeContainer) {
		const siblingCode = target.parentElement?.querySelector("pre, code");
		if (siblingCode) codeContainer = siblingCode;
	}

	if (!codeContainer) {
		console.warn("未找到要复制的代码容器");
		return;
	}

	// 获取代码文本并处理空行
	const rawText = getCodeText(codeContainer);
	const processedText = processEmptyLines(rawText);

	try {
		await copyToClipboard(processedText);

		// 提示用户成功（若 target 是按钮，尝试修改文本或添加成功样式）
		if (target instanceof HTMLElement) {
			const btn = target as HTMLButtonElement;
			const originalText = btn.textContent || "";
			const successText = btn.getAttribute("data-copied-text") || "已复制";
			btn.textContent = successText;
			btn.classList.add("copied");

			// 恢复原始状态
			setTimeout(() => {
				btn.textContent = originalText;
				btn.classList.remove("copied");
			}, 1500);
		}
	} catch (err) {
		console.error("复制失败:", err);
		if (target instanceof HTMLElement) {
			const btn = target as HTMLButtonElement;
			const originalText = btn.textContent || "";
			const failedText = btn.getAttribute("data-failed-text") || "复制失败";
			btn.textContent = failedText;
			btn.classList.add("copy-failed");
			setTimeout(() => {
				btn.textContent = originalText;
				btn.classList.remove("copy-failed");
			}, 1500);
		}
	}
}